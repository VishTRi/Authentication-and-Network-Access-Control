# SDN Authentication and Network Access Control

**Full project documentation**

A TCP authentication service integrated with an SDN controller. Hosts must log in before they can reach a protected service; the controller dynamically grants, restricts or revokes network access using OpenFlow rules.

Team: *names*  |  Repository: *link*  |  Version: *date*

---

## 1. Introduction

### 1.1 Problem

In a conventional network, any host that can route to a service can use it. This project makes access conditional: a host must authenticate over TCP, and the network itself then opens or closes the path to the protected service for that host.

### 1.2 Solution in one paragraph

A threaded TCP authentication server runs on a host inside a Mininet network. Clients send `LOGIN`, `LOGOUT` and `STATUS` commands. After a successful login the server sends a JSON command to a Ryu SDN controller, which installs OpenFlow 1.3 rules in an Open vSwitch switch so that only that host's IP can reach the services its user is allowed to use. Logout, session expiry, or repeated failed logins cause the controller to remove those rules or block the host entirely.

### 1.3 Features

- TCP authentication server and client built on low-level sockets.
- Multiple concurrent users (one thread per connection).
- Sessions with a time-to-live; automatic expiry.
- Per-user allow policies (service IP and TCP port), including valid accounts with no access.
- Default-deny protection for the service host, enforced in the switch.
- Dynamic installation and removal of flow rules on login, logout, expiry and lock-out.
- Brute-force protection: network-level lock-out after repeated failures.
- Authentication and access logs on the server and the controller; flow-statistics monitoring.
- Automated functional tests, performance experiments and a mock controller for isolated testing.

---

## 2. System Architecture

### 2.1 Overview

```
  h1, h2, h3 (clients)                       Ryu controller (root namespace)
   10.0.0.1 - 10.0.0.3                       OpenFlow 1.3 :6653   control channel :9000
        \                                          ^   |
         \                            JSON/TCP     |   | OpenFlow flow-mods
          +---- s1 (Open vSwitch) ---- auth ------+   v
         /        |                  10.0.0.100      s1 flow tables
        /         |                  TCP :5000
   root-eth0      +---- svc (protected services)
   10.0.0.254           10.0.0.200   :8080  :9090  :7070
```

### 2.2 Addressing

| Node | IP | MAC | Role |
| --- | --- | --- | --- |
| h1 .. hN | 10.0.0.1 .. 10.0.0.N | 00:00:00:00:00:01 ... | Clients |
| auth | 10.0.0.100 | 00:00:00:00:01:00 | Authentication server, TCP 5000 |
| svc | 10.0.0.200 | 00:00:00:00:02:00 | Protected services, TCP 8080, 9090, 7070 |
| root-eth0 | 10.0.0.254 | n/a | Link into the root namespace; the controller's control port is reachable here |
| s1 | n/a | n/a | Open vSwitch, OpenFlow 1.3 |

All links are 100 Mbps. The controller runs outside the virtual network, so the topology adds a link from s1 to the root namespace (`root-eth0`). The auth server reaches the controller's control channel at `10.0.0.254:9000` over this link.

### 2.3 Responsibilities

| Component | Responsibility |
| --- | --- |
| Auth clients | Send commands; show replies and latency |
| Auth server | Verify credentials, hold sessions and timeouts, count failures, log events, instruct the controller |
| Controller | Keep the switch in default deny, install and remove rules on request, learn MAC addresses, poll statistics |
| Switch | Enforce rules on every packet |
| Protected services | The resources being protected |

### 2.4 Normal behavior

- Clients can always reach the auth server; only the service host is protected.
- Before login, packets from clients to the service host are dropped.
- After login, packets from that client's IP to its allowed ports are forwarded; every other client remains blocked.
- After logout, expiry or lock-out, the access disappears.

---

## 3. Installation

### 3.1 Requirements

- Ubuntu 20.04 or 22.04 (a VM is fine; WSL is not suitable because Open vSwitch needs kernel support).
- sudo access, internet access for the install, 4 GB RAM recommended.

### 3.2 Install Mininet and Open vSwitch

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch python3-pip tcpdump
sudo service openvswitch-switch start
sudo mn --test pingall          # must end with 0% dropped
```

### 3.3 Install Ryu (Python 3.9 environment)

Ryu does not work with recent Python versions, so use a separate Python 3.9 environment:

```bash
pip install uv
uv venv --python 3.9 ryuenv
uv pip install --python ryuenv/bin/python "setuptools==65.5.0" wheel pbr
uv pip install --python ryuenv/bin/python --no-build-isolation "eventlet==0.30.2" ryu
```

Mininet, the auth server, the clients and the services use the system `python3` and only the standard library. Only the controller uses `ryuenv`.

### 3.4 Optional: plotting

```bash
pip install matplotlib        # only for tests/plot_results.py
```

---

## 4. Running the System

Run everything from the project root.

**Terminal A: controller**

```bash
ryuenv/bin/ryu-manager controller/acl_controller.py
```

When the switch connects, the log shows `SWITCH_READY ... default-deny installed`.

**Terminal B: network and servers**

```bash
sudo mn -c
sudo python3 topology/topology.py --clients 3 --session-ttl 60
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--clients` | 3 | Number of client hosts |
| `--session-ttl` | 60 | Session lifetime in seconds |
| `--no-sdn` | off | Auth server never calls the controller (baseline) |
| `--no-services` | off | Do not start the auth server and services |

This starts the auth server on `auth` and the services on `svc`, then opens the Mininet CLI.

**Example session (Mininet CLI)**

```
mininet> h1 python3 services/service_client.py --port 8080          # BLOCKED
mininet> h1 python3 auth/auth_client.py login alice alicepw         # OK ttl=60 ...
mininet> h1 python3 services/service_client.py --port 8080          # ACCESS_OK
mininet> h2 python3 services/service_client.py --port 8080          # BLOCKED (h2 not logged in)
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 table=0          # inspect rules
mininet> h1 python3 auth/auth_client.py logout
mininet> h1 python3 services/service_client.py --port 8080          # BLOCKED again
```

**Demo accounts** (defined in `auth/make_users.py`; lab use only)

| User | Password | Allowed |
| --- | --- | --- |
| alice | alicepw | svc ports 8080, 9090, 7070 |
| bob | bobpw | svc port 8080 |
| mallory | mallorypw | none (valid login, denied by policy) |

To change users or policies, edit `auth/make_users.py`, run `python3 auth/make_users.py`, and restart the auth server.

---

## 5. Authentication Server

File: `auth/auth_server.py`.

### 5.1 Networking design

- A TCP socket (`AF_INET`, `SOCK_STREAM`) with `SO_REUSEADDR`, bound to `0.0.0.0:5000`, `listen(128)`.
- `accept()` returns a connected socket; each connection gets its own daemon thread.
- Messages are text lines ending in a newline. This framing is needed because TCP is a byte stream with no message boundaries. Lines are limited to 512 bytes.
- Each connection has an idle timeout (default 30 s).
- The client's network identity is the **source IP of the TCP connection**, not anything in the message.

### 5.2 Client protocol

| Request | Replies |
| --- | --- |
| `LOGIN <user> <password>` | `OK ttl=<s> services=<ip:port;...>`; `DENY bad-credentials`; `DENY no-access-policy`; `DENY too-many-failures blocked <s>`; `DENY blocked <s>`; `DENY controller-unavailable` |
| `LOGOUT` | `OK bye`; `ERR not-logged-in` |
| `STATUS` | `OK user=<u> remaining=<s>`; `OK not-logged-in` |
| `QUIT` | closes the connection |

Other replies: `ERR usage: LOGIN <user> <password>`, `ERR unknown-command`, `ERR line-too-long`.

### 5.3 State and concurrency

| State | Content |
| --- | --- |
| `sessions` | client IP to user, expiry time, services |
| `fails` | client IP to timestamps of recent failed logins |
| `blocked` | client IP to unblock time |

All state is protected by one lock. Calls to the controller are made outside the lock so that a slow network call does not serialize other logins. A reaper thread runs once a second, expires sessions and sends `revoke` to the controller.

### 5.4 Login procedure

1. Refuse immediately if the source IP is currently blocked.
2. Verify the password: salted PBKDF2-HMAC-SHA256 (50,000 iterations), compared in constant time. Unknown users take the same hashing time as known ones.
3. On failure, record it. When failures within the window reach the limit, send `block` to the controller and refuse further logins from that IP.
4. Look up the user's allow list. An empty list means a valid account with no access, so the login is denied.
5. Send `allow` to the controller and wait for its reply.
6. If the controller replies `ok`, store the session and reply `OK`; otherwise reply `DENY controller-unavailable` (fail closed).

### 5.5 Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--host`, `--port` | 0.0.0.0, 5000 | Listen address |
| `--ctl-host`, `--ctl-port` | 10.0.0.254, 9000 | Controller control channel |
| `--session-ttl` | 60 | Session lifetime (s) |
| `--max-fails` | 3 | Failures before lock-out |
| `--fail-window` | 60 | Window for counting failures (s) |
| `--block-seconds` | 30 | Lock-out duration (s) |
| `--idle-timeout` | 30 | Idle connection timeout (s) |
| `--users` | auth/users.json | User database |
| `--log-dir` | logs/ | Log directory |
| `--no-sdn` | off | Skip controller calls (baseline) |

### 5.6 Users and policy

`auth/users.json` maps each user to a random salt, a password hash and an `allow` list of `[service IP, port]` pairs. It is generated by `auth/make_users.py`.

---

## 6. Clients and Protected Services

| File | Purpose |
| --- | --- |
| `auth/auth_client.py` | `login <user> <password>`, `logout`, `status`. Prints the reply and `latency_ms`. Exit code 0 = OK, 1 = denied, 2 = network error. Option `--server` (default 10.0.0.100). |
| `services/protected_service.py` | Listens on 8080 and 9090 (send a banner and close) and 7070 (a data sink that replies `RECEIVED <bytes>`). |
| `services/service_client.py` | Tries to connect. `ACCESS_OK` if reachable, `BLOCKED` otherwise. A dropped packet shows as a timeout; a closed port shows as an immediate refusal. `--wait-blocked` polls until access disappears. |
| `services/bulk_client.py` | Sends data to port 7070 for N seconds and prints `mbps=`. Uses a TCP half-close (`shutdown(SHUT_WR)`) so the server can report the final count. |

---

## 7. Mininet Topology

File: `topology/topology.py`.

- `build_net(n_clients, bw, ctl_ip, ctl_port)` creates one OVS switch (OpenFlow 1.3), N clients, `auth`, `svc`, and the root-namespace link. Links use `TCLink` with 100 Mbps.
- `start_net` starts the network and waits up to 20 seconds for the switch to connect to the controller.
- `start_services` and `stop_services` launch and stop the auth server and the protected services on their hosts.
- The remote controller is expected at `127.0.0.1:6653`.

---

## 8. SDN Controller

File: `controller/acl_controller.py` (Ryu, OpenFlow 1.3).

### 8.1 Flow tables

```
table 0  ACCESS CONTROL
  prio 200  ipv4_src = blocked host                            -> drop           (hard timeout = block time)
  prio 100  ipv4_src = client, ipv4_dst = svc, tcp_dst = port  -> goto table 1   (hard timeout = session TTL)
  prio  50  ipv4_dst = protected host                          -> drop           (default deny)
  prio   0  any                                                -> goto table 1
table 1  L2 FORWARDING (learning switch)
  prio   1  in_port, eth_src, eth_dst                          -> output         (idle timeout 60 s)
  prio   0  any                                                -> controller
```

The highest matching priority wins. ARP is not IPv4, so hosts can still resolve addresses and reach the auth server. Separating access control from forwarding means access rules never need to know output ports.

### 8.2 Switch events

| Event | Behavior |
| --- | --- |
| Switch connects | Delete all flows, install the table-1 miss rule, the table-0 pass-through, and the default-deny rule for each protected host |
| Packet-in | Learn the source MAC and port; forward to the learned port or flood; install a table-1 rule when the destination is known |
| Flow removed | Log expiry or deletion of allow and block rules |
| Flow stats reply | Append to `logs/flow_stats.csv`; log the dropped-packet count for protected hosts when it changes |

### 8.3 Control channel

The controller listens on TCP `0.0.0.0:9000`. Each request is one JSON line; each reply is one JSON line.

| Command | Fields | Effect |
| --- | --- | --- |
| `allow` | `ip`, `user`, `services` (list of `[dst, port]`), `ttl` (0 to 65535, 0 = permanent) | Replace the client's older allow rules; install one prio-100 rule per service with `hard_timeout = ttl` |
| `revoke` | `ip` | Delete the client's allow rules |
| `block` | `ip`, `seconds` (1 to 65535) | Delete the client's allow rules; install a prio-200 drop-all rule with a hard timeout |
| `unblock` | `ip` | Delete the block rule |
| `status` | none | Return current allowed and blocked hosts with remaining times |

Replies: `{"status":"ok", ...}` or `{"status":"error","msg":"..."}`.

**Validation:** IP addresses must parse; ports must be 1 to 65535; the destination must be a protected host (set `PROTECTED` in the controller); allow requests for a blocked host are rejected; commands are refused while no switch is connected.

### 8.4 Rule management

Rules are tagged with cookies (`0x50` default deny, `0xA1` allow, `0xB1` block). Revocation uses a non-strict delete with a cookie mask and a match on the client's source IP, so exactly that client's allow rules are removed and nothing else.

### 8.5 Monitoring and logging

- Flow statistics of table 0 are polled every 5 seconds and appended to `logs/flow_stats.csv` (time, priority, cookie, match, packets, bytes).
- Controller events are written to `logs/controller.log`: `SWITCH_READY`, `ALLOW`, `REVOKE`, `BLOCK`, `UNBLOCK`, `*_RULE_REMOVED`, `MONITOR`, `CONTROL_ERROR`.

---

## 9. Socket-SDN Integration

### 9.1 Login sequence

```
Client h1         Auth server        Controller          Switch s1
   | LOGIN alice pw    |                  |                  |
   |------------------>| verify password  |                  |
   |                   | allow 10.0.0.1   |                  |
   |                   |----------------->| flow-mods        |
   |                   |                  |----------------->|
   |                   |<---- ok ---------|                  |
   |<--- OK ttl=60 ----|                  |                  |
   | TCP to svc:8080 ---------------------------------------->| allow rule matches, forwarded
```

### 9.2 Application events and network effects

| Event | Message | Network effect |
| --- | --- | --- |
| Login success | `allow` | Allow rules for each permitted service, expiring at the session TTL |
| Logout | `revoke` | Allow rules deleted |
| Session expiry | `revoke` (and switch hard timeout) | Allow rules removed |
| Repeated failures | `block` | Drop-all rule for that IP; allow rules deleted |

### 9.3 Design decisions

- **Confirm before OK.** The auth server replies `OK` only after the controller confirms, so a client never sees success before the rules exist.
- **Two independent expiries.** The switch hard timeout and the server's reaper both end a session, so access still ends if the auth server stops.
- **Enforcement in the network.** A locked-out host's packets are dropped in the switch, so it cannot reach the auth server at all.
- **Identity from the socket.** The source IP comes from the TCP connection, so a client cannot request access for another host.
- **Controller limits its own scope.** It only opens protected hosts and validates all input rather than trusting the auth server.
- **Fail closed.** If the controller is unreachable, logins are refused; with no rules, traffic to protected hosts is dropped.

### 9.4 Failure behavior

| Failure | Result |
| --- | --- |
| Controller down | New logins refused; existing rules expire at their hard timeout |
| Auth server down | No new logins; existing rules expire at their hard timeout |
| Switch disconnects and reconnects | Controller wipes the switch and reinstalls the defaults; sessions must log in again |
| Control message malformed or invalid | Controller replies with an error; no rule change |

---

## 10. Testing

### 10.1 Automated functional tests

Run with the controller running: `sudo python3 tests/run_tests.py`. The script builds its own network, runs 17 checks with a 10 second session TTL, and writes `results/test_results.txt` plus copies of the logs.

| ID | Scenario | Expected |
| --- | --- | --- |
| T1 | h1 to svc:8080 before login | Blocked |
| T1b | h1 reaches the auth server before login | Reachable |
| T2 | alice logs in | OK |
| T3a, T3b | h1 to 8080 and 9090 after login | Allowed |
| T3c | h2 (not logged in) to 8080 | Blocked |
| T4a, T4b | bob logs in; h2 to 8080 | OK; allowed |
| T4c | h2 to 9090 as bob | Blocked by policy |
| T5a, T5b | mallory logs in; h3 to 8080 | Denied; blocked |
| T6a | three wrong passwords from h3 | Host blocked |
| T6b | correct password from the blocked host | Fails |
| T7a, T7b | alice logs out; h1 to 8080 | OK; blocked |
| T8a, T8b | new login, then wait past the TTL | Allowed, then blocked |

Record the actual results here: *fill from results/test\_results.txt*.

### 10.2 Testing the auth server without Mininet

```bash
python3 tests/mock_controller.py &
python3 services/protected_service.py &
python3 auth/auth_server.py --ctl-host 127.0.0.1 --session-ttl 10 &
python3 auth/auth_client.py --server 127.0.0.1 login alice alicepw
```

The mock controller prints every command it receives and always replies `ok`.

### 10.3 Useful inspection commands

| Purpose | Command |
| --- | --- |
| Show switch rules | `sh ovs-ofctl -O OpenFlow13 dump-flows s1 table=0` (in the Mininet CLI) |
| Listening sockets | `auth ss -tnlp`, `svc ss -tnlp` |
| Login packets | `sudo tcpdump -n -i s1-eth4 'tcp port 5000'` |
| Controller messages | `sudo tcpdump -n -A -i root-eth0 'tcp port 9000'` |
| Live logs | `tail -f logs/auth.log logs/controller.log` |

---

## 11. Performance Evaluation

Run with the controller running: `sudo python3 tests/perf.py` (add `--quick` for a short smoke test; the full run takes roughly ten minutes). Raw data goes to `results/perf_results.csv`. Then `python3 tests/plot_results.py` writes graphs and `results/summary.txt`.

### 11.1 Experiments

| ID | Question | Method | Comparison |
| --- | --- | --- | --- |
| E1 | How does login latency scale with concurrent users? | 1, 5, 10 and 20 clients log in simultaneously, 5 repetitions each; record mean and maximum latency and success count | Dynamic SDN vs auth-only (`--no-sdn`) |
| E2 | Is access revoked on logout? | Log in, log out, test reachability; record logout latency and whether the service is still reachable | Dynamic SDN vs static ACL (permanent allow rule) |
| E3 | Does access control affect throughput? | 5-second bulk transfers to port 7070, 5 runs per mode | Blocked (no login), dynamic, static ACL |

### 11.2 Baselines

- **Auth-only:** the same auth server with controller calls disabled. The latency difference isolates the cost of the SDN round trip.
- **Static ACL:** a permanent allow rule for fixed hosts, with no authentication, sessions or revocation. This represents hand-configured access control.

### 11.3 Results

*Insert your graphs (`results/e1_login_latency.png`, `results/e3_throughput.png`) and values here.*

| Metric | Dynamic SDN | Baseline | Notes |
| --- | --- | --- | --- |
| Mean login latency, 1 user | *fill* | *fill* |  |
| Mean login latency, 20 users | *fill* | *fill* |  |
| Reachable after logout | *fill* | *fill* |  |
| Throughput (Mbps) | *fill* | *fill* |  |

### 11.4 Interpretation guide

- Login latency in SDN mode includes the TCP handshake with the auth server, password hashing, and one extra TCP round trip to the controller. Latency typically rises with concurrency because of CPU contention (hashing, thread scheduling) on a single emulation host.
- Throughput should be the same in dynamic and static modes: once rules are installed the switch forwards in the data plane, and the controller is not on the data path.
- A static ACL cannot revoke access; the dynamic design can.
- Results come from an emulated network on one machine, so they show relative behavior, not absolute numbers.

---

## 12. Logs and Data Files

| File | Content |
| --- | --- |
| `logs/auth.log` | `AUTH_SERVER_START`, `LOGIN_OK` (with controller round-trip ms), `LOGIN_FAIL attempt=n/m`, `LOGIN_DENIED`, `LOGIN_REFUSED`, `HOST_BLOCKED`, `LOGOUT`, `SESSION_EXPIRED`, `CONTROLLER_ERROR`, `CONN_CLOSED` |
| `logs/controller.log` | `SWITCH_READY`, `ALLOW`, `REVOKE`, `BLOCK`, `UNBLOCK`, `ALLOW_RULE_REMOVED`, `BLOCK_RULE_REMOVED`, `MONITOR`, `CONTROL_ERROR` |
| `logs/flow_stats.csv` | Periodic packet and byte counters of the table-0 rules |
| `logs/auth_stdout.log`, `logs/service_stdout.log` | Process output on the hosts |
| `results/test_results.txt` | Pass or fail of each functional test |
| `results/perf_results.csv` | Raw performance data (experiment, mode, parameter, run, metric, value) |
| `results/summary.txt` and `*.png` | Aggregated statistics and graphs |

---

## 13. Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `ovs-vsctl` or `mn` not found, or Open vSwitch will not start | The install is incomplete. Re-run `sudo apt install -y mininet openvswitch-switch`. On a minimal kernel, install `linux-modules-extra-$(uname -r)` and run `sudo modprobe openvswitch`. WSL is not supported. |
| `switch did not connect` | The controller is not running, or Open vSwitch is not started. Run `sudo mn -c` and restart. |
| `DENY controller-unavailable` | The auth host cannot reach 10.0.0.254:9000. Test `auth ping -c 2 10.0.0.254`. If ping works, the host firewall blocks the interface: `sudo iptables -I INPUT -i root-eth0 -j ACCEPT`. |
| Always `BLOCKED` after a successful login | Check the controller log for `ALLOW`, then `dump-flows` for the priority-100 rules. |
| `OK not-logged-in` right after logging in | The session TTL has already expired. Use a longer `--session-ttl`. |
| Ryu fails to install or import | Use the Python 3.9 environment with `setuptools==65.5.0` and `--no-build-isolation`. |
| Stale state after a crash | `sudo mn -c`, `pkill -f auth_server.py`, `pkill -f protected_service.py`, restart the controller. |

---

## 14. Security Considerations and Limitations

- Credentials are sent in plaintext inside the emulated network; a real deployment needs TLS.
- Identity is the source IP address. On a real network it could be spoofed; mitigations include binding MAC address and switch port, or using 802.1X.
- The controller's control port has no authentication of its own. In this lab only the auth host and the root namespace can reach it; a real deployment needs an authenticated, encrypted channel.
- One switch and one controller, with no high availability.
- Users and sessions are held in files and memory; a production system would use a database and shared session storage.
- The demo passwords in the documentation are for lab use only.
- Performance results come from an emulation on a single machine.

---

## 15. Possible Extensions

- TLS on the client and control channels.
- Rate limiting of login attempts with OpenFlow meters.
- Multiple switches and multi-hop paths.
- Controller redundancy and session persistence.
- A REST interface instead of the line-based control channel.
- Per-session bandwidth limits or quality of service.

---

## 16. Repository Layout

```
controller/acl_controller.py   Ryu app: two-table pipeline, control channel, monitoring
auth/auth_server.py            Threaded TCP auth server: sessions, timeouts, lock-out, logs
auth/auth_client.py            TCP client: login, logout, status
auth/make_users.py, users.json Salted password hashes and per-user allow policy
services/                      Protected services, probe client, throughput client
topology/topology.py           Mininet topology and root-namespace link
tests/run_tests.py             Automated functional tests
tests/perf.py, plot_results.py Performance experiments and graphs
tests/mock_controller.py       Fake controller for testing without Mininet
docs/                          Architecture notes and demo script
logs/, results/                Runtime logs; test and evaluation output
requirements.txt, README.md    Dependencies; quick-start guide
```

## Appendix: Message Reference

**Client to auth server** (text lines, newline-terminated): see Section 5.2.

**Auth server to controller** (JSON lines):

```
{"cmd":"allow","ip":"10.0.0.1","user":"alice","services":[["10.0.0.200",8080],["10.0.0.200",9090]],"ttl":60}
{"cmd":"revoke","ip":"10.0.0.1"}
{"cmd":"block","ip":"10.0.0.3","seconds":30}
{"cmd":"unblock","ip":"10.0.0.3"}
{"cmd":"status"}
```

**Controller replies:**

```
{"status":"ok","rules":2}
{"status":"error","msg":"host 10.0.0.3 is blocked"}
```
