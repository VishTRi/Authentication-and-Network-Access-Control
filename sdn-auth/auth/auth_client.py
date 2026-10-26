#!/usr/bin/env python3
"""TCP client for the auth server.

  auth_client.py [--server IP] login <user> <password>
  auth_client.py [--server IP] logout
  auth_client.py [--server IP] status

Prints the server reply and `latency_ms=`. Exit code 0 = OK reply, 1 = denied, 2 = network error.
"""
import argparse
import socket
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="10.0.0.100")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--timeout", type=float, default=3.0)
    sub = ap.add_subparsers(dest="cmd", required=True)
    lg = sub.add_parser("login")
    lg.add_argument("user")
    lg.add_argument("password")
    sub.add_parser("logout")
    sub.add_parser("status")
    a = ap.parse_args()

    line = "LOGIN %s %s" % (a.user, a.password) if a.cmd == "login" else a.cmd.upper()
    t0 = time.time()
    try:
        with socket.create_connection((a.server, a.port), timeout=a.timeout) as s:
            s.settimeout(a.timeout)
            s.sendall((line + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(1024)
                if not chunk:
                    break
                buf += chunk
            try:
                s.sendall(b"QUIT\n")
            except OSError:
                pass
        reply = buf.decode().strip()
    except OSError as e:
        print("ERROR %s" % type(e).__name__)
        print("latency_ms=%.2f" % ((time.time() - t0) * 1000))
        sys.exit(2)
    print(reply)
    print("latency_ms=%.2f" % ((time.time() - t0) * 1000))
    sys.exit(0 if reply.startswith("OK") else 1)


if __name__ == "__main__":
    main()
