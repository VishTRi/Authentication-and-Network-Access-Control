# Architecture

## Components
| Component | Where | Role |
|---|---|---|
| Auth clients | h1..hN | send LOGIN / LOGOUT / STATUS over TCP |
| Auth server | `auth` (10.0.0.100:5000) | verifies credentials, keeps sessions + timeouts, counts failures, logs, tells the controller |
| Controller (Ryu) | root namespace (OpenFlow :6653, control :9000) | installs/removes ACL flow rules, learning switch, monitoring |
| Switch | s1 (OVS, OpenFlow 1.3) | enforces the rules |
| Protected services | `svc` (10.0.0.200: 8080 web, 9090 admin, 7070 bulk) | resources to protect |

## Flow tables (OpenFlow 1.3)
```
table 0  ACCESS CONTROL
  prio 200  ipv4_src = blocked host                              -> drop          hard_timeout = block time
  prio 100  ipv4_src = client, ipv4_dst = svc, tcp_dst = port    -> goto table 1  hard_timeout = session TTL
  prio  50  ipv4_dst = svc                                       -> drop          (default deny)
  prio   0  any                                                  -> goto table 1
table 1  L2 FORWARDING (learning switch)
  prio   1  in_port, eth_src, eth_dst                            -> output        idle_timeout 60
  prio   0  any                                                  -> controller
```
Highest priority wins: a blocked host is dropped even if it still had an allow rule; an allowed client passes
the default deny; everyone else is dropped. ARP is not IPv4, so hosts can still resolve addresses and reach the
auth server.

## Login sequence
1. h1 connects to auth:5000 (allowed, only svc is protected) and sends `LOGIN alice alicepw`.
2. Auth server verifies the PBKDF2 hash, looks up alice's allow list in `users.json`.
3. Auth server sends `{"cmd":"allow","ip":"10.0.0.1","services":[...],"ttl":60}` to the controller.
4. Controller validates it, deletes older allow rules for that IP, installs one prio-100 rule per (service, port) with `hard_timeout=60`.
5. Controller replies `{"status":"ok"}`; only then does the auth server reply `OK ttl=60 ...` to h1 (so access exists the moment the client sees OK).
6. h1 reaches svc. Logout, expiry (auth server's reaper thread + switch hard_timeout) or a block removes the rules.

## Messages
Client <-> auth server (text lines over TCP):
```
LOGIN <user> <password>  -> OK ttl=<s> services=<ip:port;...> | DENY bad-credentials | DENY no-access-policy
                            | DENY too-many-failures blocked <s> | DENY blocked <s> | DENY controller-unavailable
LOGOUT -> OK bye | ERR not-logged-in          STATUS -> OK user=<u> remaining=<s> | OK not-logged-in
```
Auth server <-> controller (JSON line per request, one JSON reply):
```
{"cmd":"allow","ip":..,"user":..,"services":[[dst,port],..],"ttl":N}   {"cmd":"revoke","ip":..}
{"cmd":"block","ip":..,"seconds":N}   {"cmd":"unblock","ip":..}   {"cmd":"status"}
```

## Design decisions (good viva material)
- **Source IP from the socket**, not from the message: a client cannot request access for another host.
- **Controller enforces its own limits**: it only opens hosts in `PROTECTED`, validates IPs/ports/TTLs.
- **Two tables**: access control is separate from forwarding, so ACL rules never need to know output ports.
- **Hard timeout on the switch** as well as the reaper thread: access still expires if the auth server dies.
- **Fail closed**: controller down -> login refused; no rules exist -> traffic dropped.
- **Per-user policy** in `users.json` (allow list per user); empty list = valid account, no access.
- **Lock-out is done in the network**: after N failures the controller drops all traffic from that IP, so a brute-forcer cannot even reach the auth server.
- **Concurrency**: one thread per connection, shared state under a lock, network calls made outside the lock.
- **Monitoring**: controller polls table-0 flow stats every 5 s -> `flow_stats.csv` and `MONITOR` log lines (packets dropped to the protected host).
