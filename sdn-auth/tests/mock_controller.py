#!/usr/bin/env python3
"""Fake controller control-channel for testing the auth server on a laptop WITHOUT Mininet.
  python3 tests/mock_controller.py          (listens on 127.0.0.1:9000, prints every command)
  python3 auth/auth_server.py --ctl-host 127.0.0.1 --session-ttl 10
"""
import json
import socketserver
import sys
import time


class H(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            print(time.strftime("%H:%M:%S"), "CTL <-", line.decode().strip(), flush=True)
            try:
                json.loads(line)
                reply = {"status": "ok"}
            except ValueError:
                reply = {"status": "error", "msg": "bad json"}
            self.wfile.write((json.dumps(reply) + "\n").encode())


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
    S(("127.0.0.1", port), H).serve_forever()
