# Viva preparation

The rubric gives 6 marks to documentation + demo + viva, and the viva is individual. Everyone must be able to
explain the WHOLE system, not only their own part. Practice by asking each other these questions with the code open.
Answers are short on purpose: if you cannot expand an answer, re-read the file named in brackets.

## 1. SDN and OpenFlow basics
- **What is SDN?** Control plane (decisions) separated from the data plane (forwarding). A central controller programs switches.
- **Control plane vs data plane here?** Ryu app = control plane. OVS switch s1 = data plane.
- **What is OpenFlow?** Protocol between controller and switch (we use 1.3) to install/read flow entries and receive packet-ins.
- **Parts of a flow entry?** Match, priority, instructions/actions, timeouts, cookie, counters.
- **What happens on a table miss?** Table 1 miss sends the packet to the controller (packet-in); the controller learns the source MAC and forwards/floods. [acl_controller.py `_packet_in`]
- **Why two tables?** Table 0 = access control, table 1 = forwarding. ACL rules just `goto` table 1, so they never need output ports.
- **How do priorities work?** Highest matching priority wins: 200 block, 100 allow, 50 default deny, 0 pass-through.
- **hard_timeout vs idle_timeout?** Hard expires a fixed time after install (session TTL); idle expires after no traffic (used for learned MAC flows).
- **What is a cookie for?** Tags rules (allow/block/protect) so we can delete exactly those rules with a cookie mask.
- **What is a drop rule in OpenFlow?** A flow entry with no instructions.
- **Reactive vs proactive?** Forwarding is reactive (packet-in learning). Access rules are proactive: pushed by controller when an event (login) happens.
- **What does ARP have to do with this?** ARP is not IPv4, so it is not hit by the IP drop rules; hosts can still resolve MACs.

## 2. Sockets and TCP
- **Why TCP, not UDP?** Credentials and commands need reliable, ordered delivery and connection state; the assignment specifies TCP.
- **Socket call sequence?** Server: socket, bind, listen, accept, recv/send, close. Client: socket, connect, send/recv, close. [auth_server.py `serve`, auth_client.py]
- **TCP is a byte stream. How do you find message boundaries?** Newline-terminated text lines; we read with `readline` with a max length (512).
- **How do you support many clients?** One thread per accepted connection; shared state protected by a `threading.Lock`; controller calls made outside the lock so logins do not serialize.
- **Why not hold the lock during the controller call?** It would make all logins wait on one network round trip (hurts the concurrency experiment).
- **Error handling?** Socket timeouts (idle 30 s), max line length, malformed commands return `ERR`, controller errors retried once then fail closed, connection errors caught and logged.
- **What is SO_REUSEADDR?** Lets the server rebind its port immediately after restart (avoids TIME_WAIT bind errors).
- **What does `listen(128)` mean?** Backlog of pending connections.
- **How did you identify the user's network identity?** From the connection's source IP (`addr[0]`), not from message content. [`handle`]
- **How are passwords stored?** Salted PBKDF2-HMAC-SHA256 (50k iterations), compared with `hmac.compare_digest`. Not plaintext. [make_users.py]
- **What is the weakness?** Credentials cross the network in plaintext (no TLS), source IP can be spoofed in a real network. Be honest about this.

## 3. The integration (your key marks)
- **How does the socket application influence the network?** On LOGIN success the auth server sends JSON `allow` to the controller, which installs flow rules. LOGOUT/expiry -> `revoke`. 3 failures -> `block`. [auth_server.py `ctl`, `do_login`; acl_controller.py `process`]
- **Why does the auth server wait for the controller's reply before answering the client?** So the client never sees OK before the rules exist.
- **What if the controller is down?** Login returns `DENY controller-unavailable`. Fail closed. Existing rules still expire by hard_timeout on the switch.
- **What if the auth server dies?** Switch rules expire by hard_timeout; no new logins.
- **How does the controller reach the auth host?** A link from s1 into the root namespace (10.0.0.254), where Ryu listens on 0.0.0.0:9000. [topology.py `build_net`]
- **How is a session revoked?** Controller non-strict delete: cookie=allow, match ipv4_src=client, in table 0.
- **What if a user logs in twice?** Old rules are deleted first, then new ones installed (replace).
- **Can a client get access for another IP?** No, IP comes from the TCP socket. Spoofing the source IP is possible only in a real network; mitigation: match on MAC+port too.
- **Can the controller be abused through its port?** Only hosts that can reach 10.0.0.254:9000 (in this lab, the auth host and the root namespace). It validates inputs and only opens `PROTECTED` hosts. Be honest: a real system needs authentication/TLS on this channel (anyone who can reach port 9000 could send commands).

## 4. Dynamic SDN features and scenarios
- **Which dynamic behaviors did you implement?** Allow on login, revoke on logout, expire on timeout, per-user per-port policy, brute-force block, monitoring of flow stats.
- **Brute force scenario: what happens?** After 3 bad logins in 60 s the auth server asks the controller to drop all traffic from that IP for 30 s (prio 200). The host cannot even reach the auth server. It auto-unblocks by hard_timeout.
- **Unauthorized scenario?** Unauthenticated host or wrong port: SYN is dropped by the default-deny rule and the client times out. Counters in `flow_stats.csv` show the drops.
- **Policy example?** bob is allowed 8080 only: a prio-100 rule exists only for 8080, so 9090 hits the default deny.
- **How is monitoring done?** The controller polls table-0 flow stats every 5 s, writes CSV, logs the number of dropped packets.

## 5. Performance evaluation
- **Metrics?** Login latency vs concurrent users (E1), revocation behavior (E2), TCP throughput (E3).
- **Baseline?** Static ACL: permanent allow rule for fixed hosts, no authentication, no sessions. For login cost the baseline is the same auth server with no controller calls (`--no-sdn`).
- **What did you find?** (Fill in from your results.) Expected shape: SDN adds one controller round trip (a few ms) to login; throughput is the same because after the rules exist the data path is identical; static ACL cannot revoke.
- **Why is throughput the same?** Rules are installed once; forwarding is done in the switch at line rate. The controller is not in the data path.
- **Why does login latency grow with users?** More concurrent TCP handshakes, PBKDF2 hashing (CPU), controller handling more requests, Mininet hosts share one CPU.
- **How many repetitions and why?** 5 runs per setting; report mean and spread to show variation.
- **Limitations of the experiment?** Emulation on one machine (shared CPU), small topology, links limited to 100 Mbps, results are relative not absolute.

## 6. Questions about "what if I change X?" (practice live)
- Change the session TTL: where? (`--session-ttl`, topology.py `start_services`)
- Add a user or change who may access what: `auth/make_users.py`, rerun, restart the auth server.
- Protect a second host: add its IP to `PROTECTED` in the controller and to users' allow lists.
- Change the failure threshold or block time: `--max-fails`, `--block-seconds`.
- Why did a rule disappear after 60 s? hard_timeout = session TTL.
- Show me the rules for this user right now: `sh ovs-ofctl -O OpenFlow13 dump-flows s1 table=0`.
- Walk me from `h1 ... login` to the first successful packet: use the 6-step sequence in `docs/ARCHITECTURE.md`.

## 7. Prepare as a team
- Fill the ownership table in the report. Everyone also reads the other parts.
- Each person: give a 2-minute walkthrough of the whole flow with the code open, without notes.
- Be ready to run any single command from `docs/DEMO.md` and explain the output.
- Say "I don't know, but I would check X" rather than guessing. State limitations yourselves (plaintext, source-IP identity, single controller); examiners respect honest scoping.
