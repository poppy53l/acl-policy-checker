"""Run with:  python -m unittest discover -s tests -v   (from the project root)"""
import ipaddress
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import acl_checker as ac  # noqa: E402

TOPOLOGY = ac.load_json(ROOT / "network" / "topology.json")
POLICY = ac.load_json(ROOT / "network" / "policy.json")


def run(config_name):
    config = ac.load_json(ROOT / "configs" / f"{config_name}.json")
    return ac.compare(TOPOLOGY, POLICY, config)


def kinds(results, kind):
    return {(r["flow"].src_name, r["flow"].dst_name, r["flow"].service)
            for r in results if r["kind"] == kind}


def flow(src_ip, dst_ip, protocol="tcp", port=80):
    return ac.Flow("a", "b", ipaddress.ip_address(src_ip), ipaddress.ip_address(dst_ip),
                   "x", protocol, port)


class RuleMatching(unittest.TestCase):
    def test_port_must_match(self):
        rule = {"action": "permit", "protocol": "tcp", "src": "any", "dst": "any", "dst_port": 80}
        self.assertTrue(ac.rule_matches(rule, flow("10.0.0.1", "10.0.0.2", "tcp", 80)))
        self.assertFalse(ac.rule_matches(rule, flow("10.0.0.1", "10.0.0.2", "tcp", 443)))

    def test_protocol_ip_matches_everything(self):
        rule = {"action": "deny", "protocol": "ip", "src": "any", "dst": "any"}
        self.assertTrue(ac.rule_matches(rule, flow("10.0.0.1", "10.0.0.2", "icmp", None)))

    def test_subnet_membership(self):
        rule = {"action": "permit", "protocol": "ip", "src": "10.0.0.0/24", "dst": "any"}
        self.assertTrue(ac.rule_matches(rule, flow("10.0.0.5", "8.8.8.8")))
        self.assertFalse(ac.rule_matches(rule, flow("10.0.1.5", "8.8.8.8")))

    def test_first_match_wins_and_implicit_deny(self):
        rules = [
            {"action": "deny", "protocol": "tcp", "src": "any", "dst": "any", "dst_port": 22},
            {"action": "permit", "protocol": "ip", "src": "any", "dst": "any"},
        ]
        self.assertFalse(ac.evaluate_acl(rules, flow("1.1.1.1", "2.2.2.2", "tcp", 22))[0])
        self.assertTrue(ac.evaluate_acl(rules, flow("1.1.1.1", "2.2.2.2", "tcp", 80))[0])
        self.assertFalse(ac.evaluate_acl([rules[0]], flow("1.1.1.1", "2.2.2.2", "tcp", 80))[0])

    def test_dst_port_rejected_for_ip_protocol(self):
        with self.assertRaises(ValueError):
            ac.validate_rule({"action": "permit", "protocol": "ip", "src": "any",
                              "dst": "any", "dst_port": 80})


class Scenarios(unittest.TestCase):
    def test_correct_config_matches_policy(self):
        results = run("correct")
        self.assertEqual(len(results), 100)  # 5 hosts * 4 others * 5 services
        self.assertEqual([r for r in results if r["kind"] != "OK"], [])

    def test_broad_permit_exposes_other_internal_hosts(self):
        v = kinds(run("bug_broad_permit"), "VIOLATION")
        self.assertIn(("guest-laptop", "web-server", "http"), v)
        self.assertIn(("guest-laptop", "staff-pc", "http"), v)

    def test_rule_order_shadows_deny(self):
        results = run("bug_rule_order")
        self.assertIn(("web-server", "db-server", "ssh"), kinds(results, "VIOLATION"))
        self.assertNotIn(("web-server", "db-server", "mysql"), kinds(results, "VIOLATION"))
        self.assertEqual(kinds(results, "OUTAGE"), set())

    def test_missing_permit_is_an_outage_not_a_violation(self):
        results = run("bug_missing_permit")
        self.assertEqual(kinds(results, "OUTAGE"), {("staff-pc", "db-server", "mysql")})
        self.assertEqual(kinds(results, "VIOLATION"), set())

    def test_unapplied_acl_opens_guest_network(self):
        v = kinds(run("bug_unapplied_acl"), "VIOLATION")
        self.assertIn(("guest-laptop", "db-server", "mysql"), v)
        self.assertEqual(len(v), 18)

    def test_wrong_direction_behaves_like_no_acl_for_guests(self):
        self.assertEqual(kinds(run("bug_wrong_direction"), "VIOLATION"),
                         kinds(run("bug_unapplied_acl"), "VIOLATION"))


class Router(unittest.TestCase):
    def test_same_subnet_traffic_is_not_filtered(self):
        extra = dict(TOPOLOGY)
        config = ac.load_json(ROOT / "configs" / "correct.json")
        router = ac.Router(extra, config)
        allowed, why = router.check(flow("192.168.10.10", "192.168.10.20", "tcp", 22))
        self.assertTrue(allowed)
        self.assertIn("same subnet", why)


if __name__ == "__main__":
    unittest.main()
