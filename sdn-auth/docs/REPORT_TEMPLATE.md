# Report outline (submit with the repo; maps to the rubric)

1. **Problem and objectives** (Problem Understanding, 2): what is being built and why SDN fits.
2. **Architecture** (2): diagram, components, communication flow, expected network behavior (use `docs/ARCHITECTURE.md`).
3. **TCP implementation** (4): socket call sequence, threading, message protocol, framing, error handling, timeouts.
4. **Mininet + SDN implementation** (4): topology, two-table pipeline, rule table with priorities, controller functions.
5. **Socket-SDN integration** (3): the auth -> controller channel, sequence diagram, what events trigger which rules.
6. **Testing** (2 + 4): table of the 17 checks in `tests/run_tests.py` with expected vs actual; screenshots of `dump-flows` before/after login.
7. **Dynamic SDN features** (6): allow on login, revoke on logout/expiry, block on brute force, per-user policy, monitoring.
8. **Challenging scenarios** (4): brute-force lock-out; controller failure (fail closed); optionally spoofing discussion.
9. **Performance evaluation** (5): metrics (login latency, concurrency scaling, revocation, throughput), method (repetitions, concurrency levels), graphs, baseline comparison, explanation of results, limits of emulation.
10. **Limitations and future work**: TLS, 802.1X, HA controller, rate limiting at the switch (meters).
11. **How to reproduce**: copy the README steps.
12. **Individual contributions**: table (member -> components).

## Baseline comparison to present
| Aspect | Static ACL (hand-written permanent rules) | Dynamic (this project) |
|---|---|---|
| Who gets access | fixed IP list | whoever authenticates, per user policy |
| Revocation | operator must edit rules | automatic: logout, timeout, lock-out |
| Brute-force handling | none | host dropped in the network |
| Throughput after allow | same data path (measured) | same data path (measured) |
| Extra cost | none | login latency (measured in E1), controller round trip |
