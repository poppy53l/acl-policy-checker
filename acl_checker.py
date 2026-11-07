"""ACL policy checker.

Question: does a set of router ACLs actually enforce the security policy
the administrator *intended*?

Method: model a small routed network, evaluate every (source host,
destination host, service) combination against the ACLs the way a router
would (first match wins, implicit deny at the end), and compare the result
with an intended policy written separately in plain terms.

Two kinds of mismatch are reported:
  VIOLATION - the ACLs allow something the policy forbids   (security hole)
  OUTAGE    - the ACLs block something the policy requires  (broken service)

Usage:
    python acl_checker.py configs/correct.json
    python acl_checker.py configs/bug_broad_permit.json --show-all
    python acl_checker.py --all
"""

import argparse
import ipaddress
import json
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).parent

# service name -> (protocol, destination port). ICMP has no port.
SERVICES = {
    "http": ("tcp", 80),
    "https": ("tcp", 443),
    "ssh": ("tcp", 22),
    "mysql": ("tcp", 3306),
    "icmp": ("icmp", None),
}

VALID_PROTOCOLS = {"ip", "tcp", "udp", "icmp"}


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Flow:
    """One connection attempt: who talks to whom, using which service."""
    src_name: str
    dst_name: str
    src_ip: ipaddress.IPv4Address
    dst_ip: ipaddress.IPv4Address
    service: str
    protocol: str
    port: object  # int or None


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def parse_net(text):
    """'any' means every address; otherwise a CIDR such as 192.168.10.0/24."""
    if text == "any":
        return ipaddress.ip_network("0.0.0.0/0")
    return ipaddress.ip_network(text, strict=False)


# --------------------------------------------------------------------------
# ACL evaluation (what the router does)
# --------------------------------------------------------------------------

def validate_rule(rule):
    if rule["action"] not in ("permit", "deny"):
        raise ValueError(f"bad action in rule: {rule}")
    if rule["protocol"] not in VALID_PROTOCOLS:
        raise ValueError(f"bad protocol in rule: {rule}")
    if rule.get("dst_port") is not None and rule["protocol"] not in ("tcp", "udp"):
        raise ValueError(f"dst_port only makes sense for tcp/udp: {rule}")


def rule_matches(rule, flow):
    """True if this ACL line applies to this flow."""
    if rule["protocol"] != "ip" and rule["protocol"] != flow.protocol:
        return False
    if flow.src_ip not in parse_net(rule["src"]):
        return False
    if flow.dst_ip not in parse_net(rule["dst"]):
        return False
    wanted_port = rule.get("dst_port")
    if wanted_port is not None and wanted_port != flow.port:
        return False
    return True


def format_rule(rule):
    port = f" eq {rule['dst_port']}" if rule.get("dst_port") is not None else ""
    return f"{rule['action']} {rule['protocol']} {rule['src']} {rule['dst']}{port}"


def evaluate_acl(rules, flow):
    """Walk the ACL top to bottom. First match wins; otherwise implicit deny."""
    for line_no, rule in enumerate(rules, start=1):
        if rule_matches(rule, flow):
            return rule["action"] == "permit", f"line {line_no} ({format_rule(rule)})"
    return False, "implicit deny at end of ACL"


class Router:
    """A single router with connected subnets and ACLs bound to interfaces."""

    def __init__(self, topology, config):
        self.interfaces = {
            name: ipaddress.ip_interface(addr)
            for name, addr in topology["interfaces"].items()
        }
        self.acls = config["acls"]
        for rules in self.acls.values():
            for rule in rules:
                validate_rule(rule)
        self.bindings = {}
        for b in config["bindings"]:
            if b["interface"] not in self.interfaces:
                raise ValueError(f"binding refers to unknown interface {b['interface']}")
            if b["direction"] not in ("in", "out"):
                raise ValueError(f"bad direction in binding: {b}")
            self.bindings[(b["interface"], b["direction"])] = b["acl"]

    def interface_for(self, ip):
        for name, iface in self.interfaces.items():
            if ip in iface.network:
                return name
        raise ValueError(f"{ip} is not in any connected subnet")

    def check(self, flow):
        """Return (allowed, explanation) for one flow crossing the router."""
        ingress = self.interface_for(flow.src_ip)
        egress = self.interface_for(flow.dst_ip)

        if ingress == egress:
            # Same subnet: switched at layer 2, the router never sees it.
            return True, "same subnet: not routed, router ACLs do not apply"

        # A packet meets the inbound ACL of its ingress interface first,
        # then the outbound ACL of its egress interface.
        notes = []
        for iface, direction in ((ingress, "in"), (egress, "out")):
            acl_name = self.bindings.get((iface, direction))
            if acl_name is None:
                continue  # nothing applied here: traffic passes
            rules = self.acls.get(acl_name)
            if rules is None:
                continue  # ACL name not defined: Cisco treats this as permit
            permitted, why = evaluate_acl(rules, flow)
            if not permitted:
                return False, f"blocked by {acl_name} ({iface} {direction}): {why}"
            notes.append(f"{acl_name} ({iface} {direction}) permitted at {why}")
        if notes:
            return True, "; ".join(notes)
        return True, f"no ACL applied on the path ({ingress} -> {egress})"


# --------------------------------------------------------------------------
# Intended policy (what the administrator wants)
# --------------------------------------------------------------------------

def intended_verdict(policy, src_name, dst_name, service):
    """First matching policy rule wins; the default is deny."""
    for rule in policy["rules"]:
        if rule["src"] not in ("any", src_name):
            continue
        if rule["dst"] not in ("any", dst_name):
            continue
        if "any" not in rule["services"] and service not in rule["services"]:
            continue
        return rule["action"] == "permit"
    return False


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------

def all_flows(topology):
    hosts = {n: ipaddress.ip_address(a) for n, a in topology["hosts"].items()}
    for src in hosts:
        for dst in hosts:
            if src == dst:
                continue
            for service, (protocol, port) in SERVICES.items():
                yield Flow(src, dst, hosts[src], hosts[dst], service, protocol, port)


def compare(topology, policy, config):
    router = Router(topology, config)
    results = []
    for flow in all_flows(topology):
        intended = intended_verdict(policy, flow.src_name, flow.dst_name, flow.service)
        actual, why = router.check(flow)
        if actual == intended:
            kind = "OK"
        elif actual and not intended:
            kind = "VIOLATION"
        else:
            kind = "OUTAGE"
        results.append({"flow": flow, "intended": intended, "actual": actual,
                        "kind": kind, "why": why})
    return results


def describe(r):
    f = r["flow"]
    return f"{f.src_name} -> {f.dst_name} [{f.service}]"


def print_report(name, description, results, show_all=False):
    violations = [r for r in results if r["kind"] == "VIOLATION"]
    outages = [r for r in results if r["kind"] == "OUTAGE"]
    print(f"=== {name} ===")
    print(description)
    print(f"{len(results)} checks | {len(violations)} violations | {len(outages)} outages")
    for r in results:
        if r["kind"] == "OK" and not show_all:
            continue
        verdict = "allowed" if r["actual"] else "blocked"
        want = "permit" if r["intended"] else "deny"
        print(f"  {r['kind']:<9} {describe(r)}: policy says {want}, network {verdict}")
        print(f"            reason: {r['why']}")
    print()


def run_one(path, show_all=False):
    topology = load_json(ROOT / "network" / "topology.json")
    policy = load_json(ROOT / "network" / "policy.json")
    config = load_json(path)
    results = compare(topology, policy, config)
    print_report(Path(path).stem, config.get("description", ""), results, show_all)
    return results


def main():
    parser = argparse.ArgumentParser(description="Check router ACLs against an intended policy.")
    parser.add_argument("config", nargs="?", help="ACL configuration JSON file")
    parser.add_argument("--all", action="store_true", help="run every file in configs/")
    parser.add_argument("--show-all", action="store_true", help="also print checks that match")
    args = parser.parse_args()

    if args.all:
        paths = sorted((ROOT / "configs").glob("*.json"))
    elif args.config:
        paths = [Path(args.config)]
    else:
        parser.error("give a config file or --all")

    mismatches = 0
    for p in paths:
        results = run_one(p, args.show_all)
        mismatches += sum(1 for r in results if r["kind"] != "OK")
    sys.exit(1 if mismatches else 0)


if __name__ == "__main__":
    main()
