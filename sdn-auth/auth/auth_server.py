#!/usr/bin/env python3
"""
TCP authentication server for the SDN access-control project.

Runs on the `auth` host in Mininet. Clients log in over TCP; on success the
server asks the SDN controller (JSON lines over TCP) to open the protected
service for that client's IP. Logout, expiry or repeated failures make the
controller revoke or block the host.

Client protocol (one text line per message, '\\n' terminated):
    LOGIN <user> <password>  -> OK ttl=<s> services=<ip:port;...> | DENY <reason>
    LOGOUT                   -> OK bye | ERR not-logged-in
    STATUS                   -> OK user=<u> remaining=<s> | OK not-logged-in
    QUIT                     -> connection closed

The client's network identity is its source IP, taken from the TCP connection
itself, never from the message (so a client cannot ask for access for
someone else's IP).
"""
import argparse
import hashlib
import hmac
import json
import logging
import os
import socket
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PBKDF2_ITER = 50_000
MAX_LINE = 512
log = logging.getLogger("auth")


class AuthServer:
    def __init__(self, args):
        self.a = args
        with open(args.users) as f:
            self.users = json.load(f)
        self.lock = threading.Lock()
        self.sessions = {}   # ip -> {user, expires, services}
        self.fails = {}      # ip -> [timestamps of recent failures]
        self.blocked = {}    # ip -> unblock time

    # ---------- controller channel ----------
    def ctl(self, msg):
        """Send one JSON command to the SDN controller. Returns reply dict or None."""
        if self.a.no_sdn:
            return {"status": "ok", "sdn": "disabled"}
        payload = (json.dumps(msg) + "\n").encode()
        for _ in range(2):
            try:
                with socket.create_connection((self.a.ctl_host, self.a.ctl_port), timeout=3) as s:
                    s.sendall(payload)
                    buf = b""
                    while not buf.endswith(b"\n"):
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                return json.loads(buf.decode())
            except (OSError, ValueError) as e:
                log.warning("CONTROLLER_ERROR cmd=%s err=%s", msg.get("cmd"), e)
                time.sleep(0.2)
        return None

    # ---------- authentication ----------
    def verify(self, user, pw):
        rec = self.users.get(user)
        salt = bytes.fromhex(rec["salt"]) if rec else b"\x00" * 16
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITER).hex()
        return rec is not None and hmac.compare_digest(dk, rec["hash"])

    def register_failure(self, ip, user):
        now = time.time()
        with self.lock:
            recent = [t for t in self.fails.get(ip, []) if now - t < self.a.fail_window]
            recent.append(now)
            self.fails[ip] = recent
            attempt = len(recent)
            trip = attempt >= self.a.max_fails
            if trip:
                self.fails.pop(ip, None)
                self.blocked[ip] = now + self.a.block_seconds
                self.sessions.pop(ip, None)
        log.warning("LOGIN_FAIL ip=%s user=%r attempt=%d/%d", ip, user, attempt, self.a.max_fails)
        if trip:
            self.ctl({"cmd": "block", "ip": ip, "seconds": self.a.block_seconds})
            log.warning("HOST_BLOCKED ip=%s seconds=%d", ip, self.a.block_seconds)
            return "DENY too-many-failures blocked %d" % self.a.block_seconds
        return "DENY bad-credentials"

    def do_login(self, ip, user, pw):
        now = time.time()
        with self.lock:
            until = self.blocked.get(ip, 0)
        if until > now:
            log.warning("LOGIN_REFUSED ip=%s user=%r reason=blocked", ip, user)
            return "DENY blocked %d" % (int(until - now) + 1)
        if len(user) > 32 or len(pw) > 128 or not self.verify(user, pw):
            return self.register_failure(ip, user)
        services = self.users[user]["allow"]
        if not services:
            log.info("LOGIN_DENIED ip=%s user=%r reason=policy-no-access", ip, user)
            return "DENY no-access-policy"
        ttl = self.a.session_ttl
        t0 = time.time()
        res = self.ctl({"cmd": "allow", "ip": ip, "user": user, "services": services, "ttl": ttl})
        ctl_ms = (time.time() - t0) * 1000
        if not res or res.get("status") != "ok":
            log.error("LOGIN_FAILED ip=%s user=%r reason=controller %s", ip, user, res)
            return "DENY controller-unavailable"
        with self.lock:
            self.sessions[ip] = {"user": user, "expires": time.time() + ttl, "services": services}
            self.fails.pop(ip, None)
        svc = ";".join("%s:%s" % (d, p) for d, p in services)
        log.info("LOGIN_OK ip=%s user=%r ttl=%d ctl_ms=%.1f services=%s", ip, user, ttl, ctl_ms, svc)
        return "OK ttl=%d services=%s" % (ttl, svc)

    def do_logout(self, ip):
        with self.lock:
            s = self.sessions.pop(ip, None)
        if not s:
            return "ERR not-logged-in"
        if self.ctl({"cmd": "revoke", "ip": ip}) is None:
            log.error("REVOKE_FAILED ip=%s (rules will still expire by timeout)", ip)
        log.info("LOGOUT ip=%s user=%r", ip, s["user"])
        return "OK bye"

    def do_status(self, ip):
        with self.lock:
            s = self.sessions.get(ip)
        if not s:
            return "OK not-logged-in"
        return "OK user=%s remaining=%d" % (s["user"], max(0, int(s["expires"] - time.time())))

    def dispatch(self, ip, line):
        cmd = line.split(" ", 1)[0].upper()
        if cmd == "LOGIN":
            parts = line.split(" ", 2)
            if len(parts) != 3 or not parts[1] or not parts[2]:
                return "ERR usage: LOGIN <user> <password>"
            return self.do_login(ip, parts[1], parts[2])
        if cmd == "LOGOUT":
            return self.do_logout(ip)
        if cmd == "STATUS":
            return self.do_status(ip)
        if cmd == "QUIT":
            return None
        return "ERR unknown-command"

    # ---------- networking ----------
    def handle(self, conn, addr):
        ip = addr[0]
        conn.settimeout(self.a.idle_timeout)
        rfile = conn.makefile("rb")
        try:
            while True:
                raw = rfile.readline(MAX_LINE + 1)
                if not raw:
                    break
                if len(raw) > MAX_LINE and not raw.endswith(b"\n"):
                    conn.sendall(b"ERR line-too-long\n")
                    break
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                reply = self.dispatch(ip, line)
                if reply is None:
                    break
                conn.sendall((reply + "\n").encode())
        except OSError as e:          # timeout, reset, broken pipe
            log.info("CONN_CLOSED ip=%s reason=%s", ip, e)
        finally:
            try:
                rfile.close()
                conn.close()
            except OSError:
                pass

    def reaper(self):
        """Expire sessions and tell the controller to revoke them."""
        while True:
            time.sleep(1)
            now = time.time()
            with self.lock:
                dead = [(ip, self.sessions.pop(ip)["user"])
                        for ip, s in list(self.sessions.items()) if s["expires"] <= now]
                for ip in [i for i, t in self.blocked.items() if t <= now]:
                    self.blocked.pop(ip)
            for ip, user in dead:
                self.ctl({"cmd": "revoke", "ip": ip})
                log.info("SESSION_EXPIRED ip=%s user=%r", ip, user)

    def serve(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.a.host, self.a.port))
        srv.listen(128)
        threading.Thread(target=self.reaper, daemon=True).start()
        log.info("AUTH_SERVER_START %s:%d controller=%s:%d ttl=%ds no_sdn=%s", self.a.host, self.a.port,
                 self.a.ctl_host, self.a.ctl_port, self.a.session_ttl, self.a.no_sdn)
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--ctl-host", default="10.0.0.254")
    ap.add_argument("--ctl-port", type=int, default=9000)
    ap.add_argument("--session-ttl", type=int, default=60)
    ap.add_argument("--max-fails", type=int, default=3)
    ap.add_argument("--fail-window", type=int, default=60)
    ap.add_argument("--block-seconds", type=int, default=30)
    ap.add_argument("--idle-timeout", type=int, default=30)
    ap.add_argument("--users", default=os.path.join(ROOT, "auth", "users.json"))
    ap.add_argument("--log-dir", default=os.path.join(ROOT, "logs"))
    ap.add_argument("--no-sdn", action="store_true", help="auth only, never call the controller (baseline)")
    args = ap.parse_args()

    os.makedirs(args.log_dir, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s.%(msecs)03d %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in (logging.FileHandler(os.path.join(args.log_dir, "auth.log")), logging.StreamHandler()):
        h.setFormatter(fmt)
        root.addHandler(h)
    AuthServer(args).serve()


if __name__ == "__main__":
    main()
