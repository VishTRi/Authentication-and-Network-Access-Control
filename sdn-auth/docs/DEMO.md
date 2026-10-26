# Demo scripts

Start: controller in terminal A, `sudo python3 topology/topology.py --clients 3 --session-ttl 30` in terminal B.
Keep a third terminal on `tail -f logs/auth.log logs/controller.log` and show it on screen.

## D1 demo (basic end-to-end, ~4 min)
1. Show the architecture diagram (README).
2. `h1 python3 services/service_client.py --port 8080` -> BLOCKED. `sh ovs-ofctl -O OpenFlow13 dump-flows s1 table=0` -> default-deny rule.
3. `h1 python3 auth/auth_client.py login alice alicepw` -> OK. Dump flows again: new prio-100 rules.
4. `h1 python3 services/service_client.py --port 8080` -> ACCESS_OK.
5. `h2 python3 services/service_client.py --port 8080` -> still BLOCKED (access is per host).
6. Wrong password: `h2 python3 auth/auth_client.py login bob nope` -> DENY.

## D2 demo (final, ~8 min)
1. Per-user policy: bob logs in on h2: 8080 ok, 9090 blocked. mallory logs in: DENY no-access-policy.
2. Concurrent users: h1, h2, h3 logged in together; `dump-flows` shows all rules.
3. Revocation: `h1 ... logout` -> blocked instantly; flows gone.
4. Timeout: login, wait 30 s, access disappears; show `ALLOW_RULE_REMOVED reason=hard-timeout` in controller.log.
5. Challenge A, brute force: 3 wrong passwords from h3 -> `HOST_BLOCKED`; correct password from h3 now times out; `dump-flows` shows the prio-200 drop; auto-unblocks after 30 s.
6. Challenge B, controller failure: stop the controller, h1 login -> `DENY controller-unavailable` (fail closed). Restart controller and show recovery.
7. Results: `sudo python3 tests/run_tests.py` output (or `results/test_results.txt`), graphs from `tests/plot_results.py`, baseline comparison.
8. Show monitoring: `cat logs/flow_stats.csv | tail`, `MONITOR` lines.

## Checklist before the demo
- `sudo mn -c`, OVS running, fresh controller, `logs/` cleared.
- Passwords/users as documented. Rehearse twice. Know who explains which part.
