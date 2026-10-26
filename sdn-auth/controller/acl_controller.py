#!/usr/bin/env python3
"""
SDN access-control controller (Ryu, OpenFlow 1.3).

Run:  ryu-manager controller/acl_controller.py

Two flow tables
  table 0  ACCESS CONTROL   (this app edits it dynamically)
      prio 200  ipv4_src=<blocked host>                       -> DROP        (lock-out after failed logins)
      prio 100  ipv4_src=<client>, ipv4_dst=<svc>, tcp_dst=<p> -> goto 1      (per-session allow, hard_timeout=session TTL)
      prio  50  ipv4_dst=<protected host>                     -> DROP        (default deny)
      prio   0  anything else                                 -> goto 1
  table 1  L2 FORWARDING    (plain learning switch; table-miss -> controller)

Control channel (TCP 9000, one JSON object per line, one JSON reply per line).
Used by the auth server (and the perf scripts):
  {"cmd":"allow","ip":"10.0.0.1","user":"alice","services":[["10.0.0.200",8080]],"ttl":60}
  {"cmd":"revoke","ip":"10.0.0.1"}
  {"cmd":"block","ip":"10.0.0.3","seconds":30}
  {"cmd":"unblock","ip":"10.0.0.3"}
  {"cmd":"status"}
"""
import csv
import ipaddress
import json
import logging
import os
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ether_types, ethernet, packet
from ryu.ofproto import ofproto_v1_3

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_DIR = os.path.join(ROOT, "logs")
STATS_CSV = os.path.join(LOG_DIR, "flow_stats.csv")

PROTECTED = {"10.0.0.200"}          # hosts that are default-deny
CONTROL_ADDR = ("0.0.0.0", 9000)
STATS_INTERVAL = 5                  # seconds between flow-stat polls

ACL_TABLE, FWD_TABLE = 0, 1
PRIO_DEFAULT, PRIO_PROTECT, PRIO_ALLOW, PRIO_BLOCK = 0, 50, 100, 200
COOKIE_PROTECT, COOKIE_ALLOW, COOKIE_BLOCK = 0x50, 0xA1, 0xB1
FULL_MASK = 0xFFFFFFFFFFFFFFFF
ETH_IP = 0x0800
REASONS = {0: "idle-timeout", 1: "hard-timeout(expired)", 2: "deleted", 3: "group-delete"}


class AclController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dp = None
        self.mac_to_port = {}
        self.allowed = {}      # ip -> {"user", "expires", "services"}
        self.blocked = {}      # ip -> expires
        self._last_drops = -1
        os.makedirs(LOG_DIR, exist_ok=True)
        fh = logging.FileHandler(os.path.join(LOG_DIR, "controller.log"))
        fh.setFormatter(logging.Formatter("%(asctime)s.%(msecs)03d %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S"))
        self.logger.addHandler(fh)
        self.logger.setLevel(logging.INFO)
        hub.spawn(self._control_server)
        hub.spawn(self._stats_loop)

    # ------------------------------------------------------------------ flow helpers
    def _flow(self, table, prio, match, actions=None, goto=None, cookie=0, idle=0, hard=0, notify=False):
        ofp, p = self.dp.ofproto, self.dp.ofproto_parser
        inst = []
        if actions:
            inst.append(p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions))
        if goto is not None:
            inst.append(p.OFPInstructionGotoTable(goto))
        flags = ofp.OFPFF_SEND_FLOW_REM if notify else 0
        self.dp.send_msg(p.OFPFlowMod(
            datapath=self.dp, cookie=cookie, table_id=table, command=ofp.OFPFC_ADD,
            idle_timeout=idle, hard_timeout=hard, priority=prio, flags=flags,
            match=match, instructions=inst))          # no instructions == drop

    def _delete(self, table, match, cookie):
        """Non-strict delete: removes every flow of this cookie whose match is at least as specific."""
        ofp, p = self.dp.ofproto, self.dp.ofproto_parser
        self.dp.send_msg(p.OFPFlowMod(
            datapath=self.dp, cookie=cookie, cookie_mask=FULL_MASK, table_id=table,
            command=ofp.OFPFC_DELETE, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=match))

    # ------------------------------------------------------------------ OpenFlow events
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features(self, ev):
        dp = ev.msg.datapath
        ofp, p = dp.ofproto, dp.ofproto_parser
        self.dp = dp
        self.mac_to_port, self.allowed, self.blocked = {}, {}, {}
        # start from a clean switch
        dp.send_msg(p.OFPFlowMod(datapath=dp, table_id=ofp.OFPTT_ALL, command=ofp.OFPFC_DELETE,
                                 out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=p.OFPMatch()))
        # table 1: unknown -> controller (learning switch)
        self._flow(FWD_TABLE, 0, p.OFPMatch(),
                   actions=[p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])
        # table 0: default pass-through, default deny for protected hosts
        self._flow(ACL_TABLE, PRIO_DEFAULT, p.OFPMatch(), goto=FWD_TABLE)
        for ip in PROTECTED:
            self._flow(ACL_TABLE, PRIO_PROTECT, p.OFPMatch(eth_type=ETH_IP, ipv4_dst=ip),
                       cookie=COOKIE_PROTECT)
        self.logger.info("SWITCH_READY dpid=%s default-deny installed for %s", dp.id, sorted(PROTECTED))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, p = dp.ofproto, dp.ofproto_parser
        in_port = msg.match["in_port"]
        eth = packet.Packet(msg.data).get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        table = self.mac_to_port.setdefault(dp.id, {})
        table[eth.src] = in_port
        out_port = table.get(eth.dst, ofp.OFPP_FLOOD)
        actions = [p.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:
            self._flow(FWD_TABLE, 1, p.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src),
                       actions=actions, idle=60)
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(p.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
                                   actions=actions, data=data))

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed(self, ev):
        msg = ev.msg
        if msg.cookie not in (COOKIE_ALLOW, COOKIE_BLOCK):
            return
        kind = "ALLOW_RULE" if msg.cookie == COOKIE_ALLOW else "BLOCK_RULE"
        self.logger.info("%s_REMOVED reason=%s packets=%d match=%s", kind,
                         REASONS.get(msg.reason, msg.reason), msg.packet_count, msg.match)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _stats_reply(self, ev):
        now = time.time()
        new = not os.path.exists(STATS_CSV)
        with open(STATS_CSV, "a", newline="") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["time", "priority", "cookie", "match", "packets", "bytes"])
            for s in ev.msg.body:
                if s.priority == PRIO_DEFAULT:
                    continue
                w.writerow(["%.3f" % now, s.priority, hex(s.cookie), str(s.match), s.packet_count, s.byte_count])
                if s.priority == PRIO_PROTECT and s.packet_count != self._last_drops:
                    self._last_drops = s.packet_count
                    self.logger.info("MONITOR dropped_packets_to_protected=%d bytes=%d", s.packet_count, s.byte_count)

    def _stats_loop(self):
        while True:
            hub.sleep(STATS_INTERVAL)
            if self.dp is not None:
                self.dp.send_msg(self.dp.ofproto_parser.OFPFlowStatsRequest(self.dp, 0, ACL_TABLE))

    # ------------------------------------------------------------------ control channel
    def _control_server(self):
        hub.StreamServer(CONTROL_ADDR, self._control_conn).serve_forever()

    def _control_conn(self, sock, addr):
        buf = b""
        try:
            sock.settimeout(10)
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        reply = self.process(line.decode("utf-8", "replace"))
                        sock.sendall((json.dumps(reply) + "\n").encode())
        except Exception as e:                       # timeout / reset: just drop the connection
            self.logger.info("CONTROL_CONN_CLOSED %s: %s", addr[0], e)
        finally:
            sock.close()

    def process(self, line):
        try:
            req = json.loads(line)
            cmd = req.get("cmd")
            if cmd == "status":
                return self._cmd_status()
            if self.dp is None:
                raise RuntimeError("no switch connected")
            handler = {"allow": self._cmd_allow, "revoke": self._cmd_revoke,
                       "block": self._cmd_block, "unblock": self._cmd_unblock}.get(cmd)
            if handler is None:
                raise ValueError("unknown cmd %r" % cmd)
            return handler(req)
        except Exception as e:
            self.logger.warning("CONTROL_ERROR %s -> %s", line.strip()[:200], e)
            return {"status": "error", "msg": str(e)}

    @staticmethod
    def _ip(value):
        return str(ipaddress.ip_address(value))      # raises ValueError on garbage

    def _cmd_allow(self, req):
        p = self.dp.ofproto_parser
        ip, user = self._ip(req.get("ip")), str(req.get("user", "?"))[:32]
        ttl = int(req.get("ttl", 60))
        if not 0 <= ttl <= 65535:
            raise ValueError("ttl out of range")
        if self.blocked.get(ip, 0) > time.time():
            raise ValueError("host %s is blocked" % ip)
        rules = []
        for dst, port in req.get("services") or []:
            dst, port = self._ip(dst), int(port)
            if dst not in PROTECTED:
                raise ValueError("%s is not a protected host" % dst)
            if not 1 <= port <= 65535:
                raise ValueError("bad port %s" % port)
            rules.append((dst, port))
        if not rules:
            raise ValueError("no services given")
        self._delete(ACL_TABLE, p.OFPMatch(eth_type=ETH_IP, ipv4_src=ip), COOKIE_ALLOW)   # replace old session
        for dst, port in rules:
            m = p.OFPMatch(eth_type=ETH_IP, ip_proto=6, ipv4_src=ip, ipv4_dst=dst, tcp_dst=port)
            self._flow(ACL_TABLE, PRIO_ALLOW, m, goto=FWD_TABLE, cookie=COOKIE_ALLOW, hard=ttl, notify=True)
        self.allowed[ip] = {"user": user, "services": rules, "expires": time.time() + ttl if ttl else None}
        self.logger.info("ALLOW ip=%s user=%s services=%s ttl=%d", ip, user, rules, ttl)
        return {"status": "ok", "rules": len(rules)}

    def _cmd_revoke(self, req):
        p = self.dp.ofproto_parser
        ip = self._ip(req.get("ip"))
        self._delete(ACL_TABLE, p.OFPMatch(eth_type=ETH_IP, ipv4_src=ip), COOKIE_ALLOW)
        known = self.allowed.pop(ip, None)
        self.logger.info("REVOKE ip=%s (had_session=%s)", ip, known is not None)
        return {"status": "ok"}

    def _cmd_block(self, req):
        p = self.dp.ofproto_parser
        ip = self._ip(req.get("ip"))
        secs = int(req.get("seconds", 30))
        if not 1 <= secs <= 65535:
            raise ValueError("seconds out of range")
        self._delete(ACL_TABLE, p.OFPMatch(eth_type=ETH_IP, ipv4_src=ip), COOKIE_ALLOW)
        self.allowed.pop(ip, None)
        self._flow(ACL_TABLE, PRIO_BLOCK, p.OFPMatch(eth_type=ETH_IP, ipv4_src=ip),
                   cookie=COOKIE_BLOCK, hard=secs, notify=True)
        self.blocked[ip] = time.time() + secs
        self.logger.warning("BLOCK ip=%s seconds=%d", ip, secs)
        return {"status": "ok"}

    def _cmd_unblock(self, req):
        p = self.dp.ofproto_parser
        ip = self._ip(req.get("ip"))
        self._delete(ACL_TABLE, p.OFPMatch(eth_type=ETH_IP, ipv4_src=ip), COOKIE_BLOCK)
        self.blocked.pop(ip, None)
        self.logger.info("UNBLOCK ip=%s", ip)
        return {"status": "ok"}

    def _cmd_status(self):
        now = time.time()
        return {"status": "ok", "switch": self.dp is not None,
                "allowed": {ip: {"user": s["user"], "services": s["services"],
                                 "remaining": None if s["expires"] is None else max(0, int(s["expires"] - now))}
                            for ip, s in self.allowed.items() if s["expires"] is None or s["expires"] > now},
                "blocked": {ip: int(t - now) for ip, t in self.blocked.items() if t > now}}
