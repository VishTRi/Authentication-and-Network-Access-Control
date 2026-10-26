#!/usr/bin/env python3
"""
Mininet topology for the SDN access-control project.

        h1 .. hN  (clients, 10.0.0.1..N)
             \\ | /
              s1 ----- auth  (10.0.0.100)  TCP auth server :5000
              |  \\
              |   `--- svc   (10.0.0.200)  protected services :8080 :9090 :7070
        root-eth0 (10.0.0.254, in the root namespace = where the Ryu controller runs)

The root-namespace link lets `auth` reach the controller's control port (9000).

Usage (controller must already be running):
    sudo python3 topology/topology.py [--clients 3] [--session-ttl 60] [--no-sdn]
"""
import argparse
import os
import sys
import time

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Node, OVSSwitch, RemoteController

try:
    from mininet.util import fixNetworkManager
except ImportError:                       # very old Mininet
    fixNetworkManager = None

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_DIR = os.path.join(ROOT, "logs")
AUTH_IP, SVC_IP, ROOT_IP = "10.0.0.100", "10.0.0.200", "10.0.0.254"
CTL_CONTROL_PORT = 9000


def build_net(n_clients=3, bw=100, ctl_ip="127.0.0.1", ctl_port=6653):
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, ipBase="10.0.0.0/24")
    net.addController("c0", controller=RemoteController, ip=ctl_ip, port=ctl_port)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    for i in range(1, n_clients + 1):
        h = net.addHost("h%d" % i, ip="10.0.0.%d/24" % i, mac="00:00:00:00:00:%02x" % i)
        net.addLink(h, s1, bw=bw)
    auth = net.addHost("auth", ip=AUTH_IP + "/24", mac="00:00:00:00:01:00")
    svc = net.addHost("svc", ip=SVC_IP + "/24", mac="00:00:00:00:02:00")
    net.addLink(auth, s1, bw=bw)
    net.addLink(svc, s1, bw=bw)
    # link into the root namespace so `auth` can reach the controller's control port
    root = Node("root", inNamespace=False)
    if fixNetworkManager:
        fixNetworkManager(root, "root-eth0")
    link = net.addLink(root, s1)
    link.intf1.setIP(ROOT_IP, 24)
    return net


def start_net(net):
    net.start()
    if not net.waitConnected(timeout=20):
        print("!! switch did not connect to the controller. Is ryu-manager running?")
        sys.exit(1)
    net.get("auth").cmd("ping -c 2 -W 1 %s > /dev/null" % ROOT_IP)       # also teaches the switch MACs


def start_services(net, session_ttl=60, no_sdn=False, max_fails=3, block_seconds=30):
    os.makedirs(LOG_DIR, exist_ok=True)
    stop_services(net)
    net.get("svc").cmd("python3 %s/services/protected_service.py > %s/service_stdout.log 2>&1 &" % (ROOT, LOG_DIR))
    net.get("auth").cmd(
        "python3 %s/auth/auth_server.py --ctl-host %s --ctl-port %d --session-ttl %d --max-fails %d "
        "--block-seconds %d %s > %s/auth_stdout.log 2>&1 &"
        % (ROOT, ROOT_IP, CTL_CONTROL_PORT, session_ttl, max_fails, block_seconds,
           "--no-sdn" if no_sdn else "", LOG_DIR))
    time.sleep(1.5)


def stop_services(net):
    net.get("auth").cmd("pkill -f auth_server.py")
    net.get("svc").cmd("pkill -f protected_service.py")
    time.sleep(0.3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clients", type=int, default=3)
    ap.add_argument("--session-ttl", type=int, default=60)
    ap.add_argument("--no-sdn", action="store_true", help="auth server without controller calls (baseline)")
    ap.add_argument("--no-services", action="store_true")
    a = ap.parse_args()
    setLogLevel("info")
    net = build_net(a.clients)
    start_net(net)
    if not a.no_services:
        start_services(net, a.session_ttl, a.no_sdn)
        print("\nServices started. Example (run from the Mininet CLI):")
        print("  h1 python3 auth/auth_client.py login alice alicepw")
        print("  h1 python3 services/service_client.py --port 8080\n")
    try:
        CLI(net)
    finally:
        stop_services(net)
        net.stop()


if __name__ == "__main__":
    main()
