#!/usr/bin/env python3
"""Throughput test against the bulk port (7070): send zeros for N seconds, report Mbps.
Prints `mbps=<x>`; prints BLOCKED and mbps=0.00 if the host cannot connect."""
import argparse
import socket
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.0.0.200")
    ap.add_argument("--port", type=int, default=7070)
    ap.add_argument("--seconds", type=float, default=5.0)
    ap.add_argument("--connect-timeout", type=float, default=2.0)
    a = ap.parse_args()
    try:
        s = socket.create_connection((a.host, a.port), timeout=a.connect_timeout)
        s.settimeout(30)
        s.recv(16)                      # READY
    except OSError as e:
        print("BLOCKED %s" % type(e).__name__)
        print("mbps=0.00")
        sys.exit(1)
    chunk = b"\0" * 65536
    sent = 0
    t0 = time.time()
    while time.time() - t0 < a.seconds:
        s.sendall(chunk)
        sent += len(chunk)
    s.shutdown(socket.SHUT_WR)
    s.recv(64)                          # RECEIVED <n> (server has drained everything)
    elapsed = time.time() - t0
    s.close()
    print("mbps=%.2f" % (sent * 8 / elapsed / 1e6))


if __name__ == "__main__":
    main()
