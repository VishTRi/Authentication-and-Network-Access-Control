#!/usr/bin/env python3
"""Protected services on the `svc` host (plain TCP, multi-threaded).

  8080  web   : sends a banner line and closes
  9090  admin : sends a banner line and closes
  7070  bulk  : sends READY, then reads and discards data until the client
                half-closes, then replies "RECEIVED <bytes>" (used for throughput tests)
"""
import argparse
import socket
import threading


def handle(conn, addr, port, bulk_port):
    try:
        conn.settimeout(30)
        if port == bulk_port:
            conn.sendall(b"READY\n")
            total = 0
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                total += len(data)
            conn.sendall(("RECEIVED %d\n" % total).encode())
        else:
            conn.sendall(("PROTECTED-SERVICE port=%d hello %s\n" % (port, addr[0])).encode())
    except OSError:
        pass
    finally:
        conn.close()


def listen(port, bulk_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(128)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr, port, bulk_port), daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ports", type=int, nargs="+", default=[8080, 9090, 7070])
    ap.add_argument("--bulk-port", type=int, default=7070)
    a = ap.parse_args()
    for p in a.ports:
        threading.Thread(target=listen, args=(p, a.bulk_port), daemon=True).start()
    print("protected services listening on", a.ports, flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
