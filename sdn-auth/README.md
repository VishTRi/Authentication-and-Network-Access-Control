# SDN Authentication and Network Access Control (TCP + Mininet + Ryu)

Hosts must log in to a TCP authentication server before they can use a protected service.
After a successful login the server tells the SDN controller, which installs OpenFlow rules for
that host. Logout, session timeout, or repeated failed logins make the controller remove the rules
or block the host.

```
 h1..hN --- s1 --- auth (TCP auth server :5000)  --JSON/TCP-->  Ryu controller (root namespace, :9000)
             |                                                        |  OpenFlow 1.3 (flow rules)
             +----- svc (protected services :8080 :9090 :7070) <------+
```
Details: `docs/ARCHITECTURE.md`. Demo scripts: `docs/DEMO.md`. 

## Layout
```
controller/acl_controller.py   Ryu app: 2-table pipeline, control channel, monitoring
auth/auth_server.py            threaded TCP auth server (sessions, timeouts, lockout, logs)
auth/auth_client.py            TCP client (login / logout / status)
auth/make_users.py, users.json salted PBKDF2 hashes + per-user allow policy
services/                      protected services, probe client, throughput client
topology/topology.py           Mininet topology (+ link into root namespace for the controller)
tests/run_tests.py             automated authorized/unauthorized scenarios
tests/perf.py, plot_results.py performance experiments + graphs
tests/mock_controller.py       test the auth server on a laptop without Mininet
```

## Setup (Ubuntu 20.04/22.04, needs sudo)
```bash
sudo apt update && sudo apt install -y mininet openvswitch-switch python3-pip
sudo service openvswitch-switch start

# Ryu needs an old Python. Ryu needs an old Python; uv can download Python 3.9:
pip install uv            # or: sudo apt install pipx && pipx install uv
uv venv --python 3.9 ryuenv
uv pip install --python ryuenv/bin/python "setuptools==65.5.0" wheel pbr
uv pip install --python ryuenv/bin/python --no-build-isolation "eventlet==0.30.2" ryu
```
Mininet and the services use the system `python3` (stdlib only). Only the controller uses `ryuenv`.

## Run
Terminal A (controller, from the project root):
```bash
ryuenv/bin/ryu-manager controller/acl_controller.py
```
Terminal B (topology + services, from the project root):
```bash
sudo python3 topology/topology.py --clients 3 --session-ttl 60
```
Then in the Mininet CLI:
```
mininet> h1 python3 services/service_client.py --port 8080                  # BLOCKED
mininet> h1 python3 auth/auth_client.py login alice alicepw                 # OK
mininet> h1 python3 services/service_client.py --port 8080                  # ACCESS_OK
mininet> h1 python3 auth/auth_client.py logout
mininet> h1 python3 services/service_client.py --port 8080                  # BLOCKED again
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 table=0                   # see the rules
```
Accounts: `alice/alicepw` (8080, 9090, 7070), `bob/bobpw` (8080 only), `mallory/mallorypw` (valid, denied by policy).
Change them in `auth/make_users.py`, then `python3 auth/make_users.py`.

## Tests and evaluation
```bash
sudo python3 tests/run_tests.py          # controller must be running; 17 checks, writes results/
sudo python3 tests/perf.py               # add --quick for a short smoke run (full run takes ~10 min)
pip install matplotlib && python3 tests/plot_results.py
```
Outputs: `results/test_results.txt`, `results/perf_results.csv`, `results/*.png`, `results/summary.txt`, logs.

## Test the auth server without Mininet
```bash
python3 tests/mock_controller.py &
python3 services/protected_service.py &
python3 auth/auth_server.py --ctl-host 127.0.0.1 --session-ttl 10 &
python3 auth/auth_client.py --server 127.0.0.1 login alice alicepw
```

## Troubleshooting
- `switch did not connect`: controller not running, or OVS not started. `sudo mn -c` then retry.
- Login says `DENY controller-unavailable`: auth host cannot reach 10.0.0.254:9000.
  Check `mininet> auth ping -c1 10.0.0.254`. If ping works but TCP does not, the host firewall blocks the
  root-namespace interface: `sudo iptables -I INPUT -i root-eth0 -j ACCEPT` (or `sudo ufw disable` in a lab VM).
- `ryu` install errors: use the Python 3.9 + `setuptools==65.5.0` + `--no-build-isolation` steps above.
- Stale state: `sudo mn -c`, `pkill -f auth_server.py`, restart the controller.
- Logs: `logs/auth.log`, `logs/controller.log`, `logs/flow_stats.csv`.

## Scope and limitations
- Credentials travel in plaintext inside the emulated network. A real deployment needs TLS.
- Identity = source IP. Mitigation in the Mininet lab is fixed MACs/ports; a real network needs 802.1X or
  MAC+port binding against spoofing.
- One controller, one switch, no controller high availability.
- Fail-closed: if the controller is unreachable, logins are refused.
