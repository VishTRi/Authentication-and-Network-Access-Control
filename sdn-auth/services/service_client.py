#!/usr/bin/env python3
"""Try to reach a protected service.

  service_client.py --host 10.0.0.200 --port 8080            -> ACCESS_OK ... | BLOCKED ...
  service_client.py --host 10.0.0.200 --port 8080 --wait-blocked
        polls until the service becomes unreachable, prints BLOCKED_AFTER_MS=<ms>

A dropped SYN shows up as a timeout, which is how a blocked host experiences the SDN drop rule.
Exit code 0 = reachable, 1 = blocked/unreachable.
"""
import argparse
import socket
import sys
import time


def attempt(host, port, timeout):
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(256).decode(errors="replace").strip()
        return True, banner, (time.time() - t0) * 1000
    except OSError as e:
        return False, type(e).__name__, (time.time() - t0) * 1000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.0.0.200")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--wait-blocked", action="store_true")
    a = ap.parse_args()

    if a.wait_blocked:
        t0 = time.time()
        while time.time() - t0 < 10:
            ok, _, _ = attempt(a.host, a.port, 0.3)
            if not ok:
                print("BLOCKED_AFTER_MS=%.1f" % ((time.time() - t0) * 1000))
                sys.exit(0)
            time.sleep(0.02)
        print("STILL_REACHABLE")
        sys.exit(1)

    ok, info, ms = attempt(a.host, a.port, a.timeout)
    print("%s %s ms=%.1f" % ("ACCESS_OK" if ok else "BLOCKED", info, ms))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
