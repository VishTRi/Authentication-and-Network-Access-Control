#!/usr/bin/env python3
"""
Performance evaluation: dynamic SDN access control vs baselines.

  1) terminal A:  ryu-manager controller/acl_controller.py
  2) terminal B:  sudo python3 tests/perf.py [--quick]
  3) any python:  python3 tests/plot_results.py        (needs matplotlib)

Experiments (all raw numbers go to results/perf_results.csv)
  E1  login latency vs number of concurrent users      dynamic SDN   vs  auth-only (no SDN calls)
  E2  logout/revocation                                dynamic SDN   vs  static ACL (permanent allow rule)
  E3  TCP throughput to the protected service          dynamic SDN   vs  static ACL   (+ blocked before login)
"""
import argparse
import csv
import json
import os
import re
import socket
import statistics
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "topology"))
from topology import AUTH_IP, SVC_IP, build_net, start_net, start_services, stop_services  # noqa: E402
from mininet.log import setLogLevel  # noqa: E402

rows = []   # (experiment, mode, param, run, metric, value)


def rec(exp, mode, param, run, metric, value):
    rows.append((exp, mode, param, run, metric, round(value, 3)))


def ctl(msg):
    """Talk to the controller directly from the root namespace (used for the static-ACL baseline)."""
    with socket.create_connection(("127.0.0.1", 9000), timeout=3) as s:
        s.sendall((json.dumps(msg) + "\n").encode())
        return json.loads(s.makefile().readline())


def ms(out):
    m = re.search(r"latency_ms=([\d.]+)", out)
    return float(m.group(1)) if m else None


def A(h, *args):
    return h.cmd("python3 %s/auth/auth_client.py --server %s %s" % (ROOT, AUTH_IP, " ".join(args)))


def reach(h, port=8080):
    return "ACCESS_OK" in h.cmd("python3 %s/services/service_client.py --host %s --port %d --timeout 2" % (ROOT, SVC_IP, port))


def bulk(h, secs):
    out = h.cmd("python3 %s/services/bulk_client.py --host %s --seconds %s" % (ROOT, SVC_IP, secs))
    m = re.search(r"mbps=([\d.]+)", out)
    return float(m.group(1)) if m else 0.0


def e1_login_concurrency(net, hosts, mode, sizes, repeats):
    print("\nE1 login latency (%s)" % mode)
    for n in sizes:
        hs = hosts[:n]
        for r in range(repeats):
            for h in hs:
                A(h, "logout")
            for h in hs:
                h.sendCmd("python3 %s/auth/auth_client.py --server %s login alice alicepw" % (ROOT, AUTH_IP))
            outs = [h.waitOutput() for h in hs]
            lat = [ms(o) for o in outs if o.strip().startswith("OK") and ms(o) is not None]
            ok = len(lat)
            if lat:
                rec("E1", mode, n, r, "mean_ms", statistics.mean(lat))
                rec("E1", mode, n, r, "max_ms", max(lat))
            rec("E1", mode, n, r, "success", ok)
            print("  n=%2d run=%d ok=%d/%d mean=%.1fms" % (n, r, ok, n, statistics.mean(lat) if lat else -1))
    for h in hosts:
        A(h, "logout")


def e2_revocation(net, h1, runs):
    print("\nE2 revocation")
    for r in range(runs):                                   # dynamic
        A(h1, "login", "alice", "alicepw")
        out = A(h1, "logout")
        rec("E2", "dynamic", 1, r, "logout_ms", ms(out) or 0)
        rec("E2", "dynamic", 1, r, "reachable_after_logout", 1 if reach(h1) else 0)
    for r in range(runs):                                   # static ACL baseline
        ctl({"cmd": "allow", "ip": "10.0.0.1", "user": "static", "ttl": 0, "services": [[SVC_IP, 8080]]})
        A(h1, "logout")                                     # nothing to log out of: static rules ignore sessions
        rec("E2", "static", 1, r, "reachable_after_logout", 1 if reach(h1) else 0)
        ctl({"cmd": "revoke", "ip": "10.0.0.1"})
    print("  done")


def e3_throughput(net, h1, secs, runs):
    print("\nE3 throughput")
    for r in range(runs):
        rec("E3", "blocked(no login)", 1, r, "mbps", bulk(h1, 1))
    for r in range(runs):
        A(h1, "login", "alice", "alicepw")
        rec("E3", "dynamic", 1, r, "mbps", bulk(h1, secs))
        A(h1, "logout")
    for r in range(runs):
        ctl({"cmd": "allow", "ip": "10.0.0.1", "user": "static", "ttl": 0, "services": [[SVC_IP, 7070]]})
        rec("E3", "static", 1, r, "mbps", bulk(h1, secs))
        ctl({"cmd": "revoke", "ip": "10.0.0.1"})
    print("  done")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="fewer repetitions (smoke test)")
    a = ap.parse_args()
    sizes = (1, 5) if a.quick else (1, 5, 10, 20)
    repeats, secs, runs = (2, 2, 2) if a.quick else (5, 5, 5)

    setLogLevel("warning")
    net = build_net(max(sizes))
    start_net(net)
    hosts = [net.get("h%d" % i) for i in range(1, max(sizes) + 1)]
    try:
        start_services(net, session_ttl=600)
        e1_login_concurrency(net, hosts, "dynamic-SDN", sizes, repeats)
        start_services(net, session_ttl=600, no_sdn=True)
        e1_login_concurrency(net, hosts, "auth-only", sizes, repeats)
        start_services(net, session_ttl=600)
        e2_revocation(net, hosts[0], 5 if not a.quick else 2)
        e3_throughput(net, hosts[0], secs, runs)
    finally:
        stop_services(net)
        net.stop()

    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    path = os.path.join(ROOT, "results", "perf_results.csv")
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["experiment", "mode", "param", "run", "metric", "value"])
        w.writerows(rows)
    print("\nwrote", path)


if __name__ == "__main__":
    main()
