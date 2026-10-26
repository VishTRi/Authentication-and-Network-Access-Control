#!/usr/bin/env python3
"""
Automated functional tests (authorized + unauthorized scenarios) on the real Mininet topology.

  1) terminal A:  ryu-manager controller/acl_controller.py
  2) terminal B:  sudo python3 tests/run_tests.py

Writes results/test_results.txt and copies the auth/controller logs into results/.
"""
import os
import shutil
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "topology"))
from topology import AUTH_IP, LOG_DIR, SVC_IP, build_net, start_net, start_services, stop_services  # noqa: E402
from mininet.log import setLogLevel  # noqa: E402

TTL = 10
results = []


def reach(h, port):
    out = h.cmd("python3 %s/services/service_client.py --host %s --port %d --timeout 2" % (ROOT, SVC_IP, port))
    return "ACCESS_OK" in out


def auth(h, *args):
    return h.cmd("python3 %s/auth/auth_client.py --server %s %s" % (ROOT, AUTH_IP, " ".join(args))).strip()


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print("[%s] %s %s" % ("PASS" if cond else "FAIL", name, detail), flush=True)


def main():
    setLogLevel("warning")
    for f in ("auth.log", "controller.log", "flow_stats.csv"):
        p = os.path.join(LOG_DIR, f)
        if os.path.exists(p) and f != "controller.log":
            os.remove(p)
    net = build_net(3)
    start_net(net)
    start_services(net, session_ttl=TTL, max_fails=3, block_seconds=30)
    h1, h2, h3 = net.get("h1"), net.get("h2"), net.get("h3")

    try:
        print("\n== Scenario 1: unauthenticated host is blocked ==")
        check("T1  h1 -> svc:8080 BLOCKED before login", not reach(h1, 8080))
        check("T1b h1 can still reach the auth server", auth(h1, "status").startswith("OK not-logged-in"))

        print("\n== Scenario 2: authorized user (alice: all services) ==")
        out = auth(h1, "login", "alice", "alicepw")
        check("T2  alice login accepted", out.startswith("OK"), out.splitlines()[0])
        check("T3a h1 -> svc:8080 allowed after login", reach(h1, 8080))
        check("T3b h1 -> svc:9090 allowed after login", reach(h1, 9090))
        check("T3c h2 (not logged in) still BLOCKED", not reach(h2, 8080))

        print("\n== Scenario 3: per-user policy (bob: web 8080 only) ==")
        out = auth(h2, "login", "bob", "bobpw")
        check("T4a bob login accepted", out.startswith("OK"))
        check("T4b h2 -> svc:8080 allowed", reach(h2, 8080))
        check("T4c h2 -> svc:9090 BLOCKED by policy", not reach(h2, 9090))

        print("\n== Scenario 4: valid account, deny policy (mallory) ==")
        out = auth(h3, "login", "mallory", "mallorypw")
        check("T5a mallory login denied by policy", out.startswith("DENY no-access-policy"), out.splitlines()[0])
        check("T5b h3 -> svc:8080 BLOCKED", not reach(h3, 8080))

        print("\n== Scenario 5: brute force -> host locked out by the SDN controller ==")
        for i in range(3):
            out = auth(h3, "login", "alice", "wrongpw")
        check("T6a 3rd wrong password triggers block", "too-many-failures" in out, out.splitlines()[0])
        out = auth(h3, "login", "alice", "alicepw")
        check("T6b correct password from blocked host fails (lock-out)", not out.startswith("OK"), out.splitlines()[0])

        print("\n== Scenario 6: logout revokes access ==")
        out = auth(h1, "logout")
        check("T7a logout accepted", out.startswith("OK"))
        check("T7b h1 -> svc:8080 BLOCKED after logout", not reach(h1, 8080))

        print("\n== Scenario 7: session timeout (%ds) ==" % TTL)
        auth(h1, "login", "alice", "alicepw")
        check("T8a h1 allowed right after login", reach(h1, 8080))
        time.sleep(TTL + 2)
        check("T8b h1 BLOCKED after session expiry", not reach(h1, 8080))
    finally:
        stop_services(net)
        net.stop()

    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    for f in ("auth.log", "controller.log", "flow_stats.csv"):
        p = os.path.join(LOG_DIR, f)
        if os.path.exists(p):
            shutil.copy(p, os.path.join(ROOT, "results", f))
    passed = sum(1 for _, ok, _ in results if ok)
    with open(os.path.join(ROOT, "results", "test_results.txt"), "w") as f:
        for name, ok, detail in results:
            f.write("%s  %s  %s\n" % ("PASS" if ok else "FAIL", name, detail))
        f.write("\n%d/%d passed\n" % (passed, len(results)))
    print("\n%d/%d tests passed (see results/)" % (passed, len(results)))
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
