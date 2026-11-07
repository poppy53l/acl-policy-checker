# ACL Policy Checker

A Python tool that compares the intended security policy of a modeled network with the permit and deny decisions of its router access control lists (ACLs). It reports unexpected access and blocked traffic that the policy requires.

A successful ping verifies one ICMP exchange. It leaves open whether other hosts or services can reach destinations that the policy is meant to protect.

## Method

1. **Network model** (`network/topology.json`): one router, five subnets (staff, guest, web server, database, internet), one host per subnet.
2. **Intended policy** (`network/policy.json`): written separately and in plain terms, for example "guests may use HTTP/HTTPS to the internet only". First match wins; the default is deny.
3. **ACL configurations** (`configs/`): extended-ACL-style rules bound to router interfaces. One correct reference configuration and five with a deliberately planted mistake.
4. **Evaluation** (`acl_checker.py`): for every ordered pair of distinct hosts and each of five services (HTTP, HTTPS, SSH, MySQL, ICMP) it simulates what the router does: inbound ACL on the ingress interface, then outbound ACL on the egress interface, first match wins, implicit deny at the end. Five hosts give 20 ordered pairs. Testing five services per pair gives 100 checks per configuration.
5. **Comparison**: each result is compared with the intended policy and classified as
   - `VIOLATION`: the network allows something the policy forbids (security hole)
   - `OUTAGE`: the network blocks something the policy requires (broken service)

## Usage

Run these commands from the project root. Python 3.8 or later is required. The checker uses only the standard library.

```bash
python acl_checker.py configs/correct.json
python acl_checker.py configs/bug_broad_permit.json
python acl_checker.py --all
python acl_checker.py configs/correct.json --show-all   # also list matching checks
python -m unittest discover -s tests -v                 # run the tests
```

## Results

| Configuration | Planted mistake | Violations | Outages |
|---|---|---|---|
| `correct` | none | 0 | 0 |
| `bug_broad_permit` | guest HTTP rule uses destination `any` | 3 | 0 |
| `bug_rule_order` | `deny ssh` placed below a broad `permit ip` | 4 | 0 |
| `bug_missing_permit` | forgot staff -> database MySQL permit | 0 | 1 |
| `bug_unapplied_acl` | guest ACL defined but not bound to the interface | 18 | 0 |
| `bug_wrong_direction` | guest ACL bound outbound instead of inbound | 18 | 0 |

In the broad-permit case, changing the guest HTTP rule’s destination to `any` allows modeled HTTP requests to three unintended hosts: the staff PC, the web server, and the database. The missing-permit case instead blocks staff access to MySQL on the database. Each mismatch reports the affected flow and the ACL decision that produced it.

## Limitations

This is a teaching-scale model, not a verification tool for real networks.

- **Request direction only.** It checks the connection initiator's packets. ACLs are stateless in this model, as with extended ACLs in Packet Tracer, so reply traffic would also need to be permitted. The reference configuration would likely break real return traffic (for example `INTERNET_IN` denies everything). Checking whether a session can complete would require modeling the return path and its ACL decisions.
- **One router, one host per subnet.** Traffic inside a subnet is switched at Layer 2 and bypasses router ACLs; the model records this but does not test Layer 2 controls such as port security or VLAN ACLs.
- **Five services only.** The checker is exhaustive over those five, not over all 65,535 ports. A rule that opens an unlisted port would not be noticed.
- **No NAT, fragments, IPv6, TCP flags or logging.**
- **Hand-written JSON, not real device configs.** It does not parse Cisco configuration syntax.
- **The intended policy is trusted.** If the policy is wrong or incomplete, the checker will faithfully confirm the wrong thing.

## Possible next steps

- Model return traffic and show which of the reference rules need adjusting.
- Parse a real `show running-config` export from a Packet Tracer lab.
- Detect shadowed or redundant rules directly, without needing a policy.
- Reason about address ranges symbolically instead of enumerating hosts.

## Project structure

```
acl_checker.py      the tool
network/            topology and intended policy
configs/            correct and buggy ACL configurations
tests/              unit tests (12)
LEARNING_GUIDE.md   walkthrough and exercises
```
