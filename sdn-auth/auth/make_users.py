#!/usr/bin/env python3
"""Generate users.json (salted PBKDF2 hashes + per-user allow policy).
Edit USERS and re-run. An empty allow list means: valid login but NO network access (deny policy)."""
import hashlib
import json
import os

PBKDF2_ITER = 50_000
SVC = "10.0.0.200"
USERS = {
    "alice":   ("alicepw",   [[SVC, 8080], [SVC, 9090], [SVC, 7070]]),  # full access
    "bob":     ("bobpw",     [[SVC, 8080]]),                            # web only
    "mallory": ("mallorypw", []),                                       # valid account, access denied by policy
}

out = {}
for name, (pw, allow) in USERS.items():
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITER)
    out[name] = {"salt": salt.hex(), "hash": h.hex(), "allow": allow}
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")
with open(path, "w") as f:
    json.dump(out, f, indent=2)
print("wrote", path)
