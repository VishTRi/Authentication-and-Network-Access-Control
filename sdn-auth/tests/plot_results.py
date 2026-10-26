#!/usr/bin/env python3
"""Make graphs + a summary table from results/perf_results.csv  (pip install matplotlib)."""
import csv
import os
import statistics
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
data = defaultdict(list)   # (exp, mode, param, metric) -> [values]
for row in csv.DictReader(open(os.path.join(R, "perf_results.csv"))):
    data[(row["experiment"], row["mode"], int(row["param"]), row["metric"])].append(float(row["value"]))


def ms(vals):
    return statistics.mean(vals), (statistics.stdev(vals) if len(vals) > 1 else 0.0)


# E1: login latency vs concurrent users
plt.figure(figsize=(6, 4))
for mode in ("dynamic-SDN", "auth-only"):
    pts = sorted((k[2], *ms(v)) for k, v in data.items() if k[:2] == ("E1", mode) and k[3] == "mean_ms")
    if pts:
        plt.errorbar([p[0] for p in pts], [p[1] for p in pts], yerr=[p[2] for p in pts], marker="o", capsize=3, label=mode)
plt.xlabel("concurrent users"); plt.ylabel("mean login latency (ms)"); plt.title("E1: login latency"); plt.legend(); plt.grid(alpha=.3)
plt.tight_layout(); plt.savefig(os.path.join(R, "e1_login_latency.png"), dpi=150)

# E3: throughput
plt.figure(figsize=(5, 4))
modes = ["blocked(no login)", "dynamic", "static"]
vals = [ms(data.get(("E3", m, 1, "mbps"), [0])) for m in modes]
plt.bar(modes, [v[0] for v in vals], yerr=[v[1] for v in vals], capsize=4)
plt.ylabel("throughput (Mbps)"); plt.title("E3: throughput to protected service"); plt.tight_layout()
plt.savefig(os.path.join(R, "e3_throughput.png"), dpi=150)

# summary table
with open(os.path.join(R, "summary.txt"), "w") as f:
    for k in sorted(data):
        m, s = ms(data[k])
        f.write("%s %-18s param=%-3d %-24s mean=%9.3f sd=%8.3f n=%d\n" % (k[0], k[1], k[2], k[3], m, s, len(data[k])))
print(open(os.path.join(R, "summary.txt")).read())
