"""
Trust-bounded LLM governance for the SDN-IoT controller (phase 4).

The fast loop (PPO, 1 Hz) keeps deciding allow / limit / block per device port. Every GOV_PERIOD
seconds the controller writes a compact snapshot of the network (gov_state.json) for an UNTRUSTED
governor process (governor.py, an LLM or a hand-written baseline). The governor answers with
directives (gov_directives.json). Every directive passes a deterministic verifier inside the
controller - the trust bound - before anything touches the network:

  offload <ip>  : trusted fast path for a device that legitimately opens many flows (e.g. an OTA
                  firmware rollout). On every switch one table-0 rule (ipv4_src = the device) sends
                  its IPv4 traffic to table 1, which holds aggregated destination-prefix routes shared
                  by all offloaded devices, so it stops generating PacketIns. Cost: one rule per switch
                  per device and direction (replies to the device are steered the same way), the routes once per switch. Capped by an OpenFlow meter (OFF_PPS) at its
                  edge port; the rules carry hard_timeout OFF_TTL, so an offload ends in the data plane
                  itself unless the controller renews it.
  revoke  <ip>  : end an offload at once (removing trust is always allowed: V6 checks only).
  release <ip>  : remove the PPO restriction of a device and pardon it for PARDON_S s.
  block   <ip>  : escalate to a drop rule.

Verifier rules (V1-V6), each logged with the verdict in gov_actions.csv:
  V1 the target is a single-device host port (never a switch link, never a protected server)
  V2 offload / release only for a port whose observed sources are its own IP (spoof share < 5 %)
  V3 block only with spoofing evidence (spoof share >= 50 %) - an LLM cannot block a clean device
  V4 budgets: at most OFF_MAX_FRAC of device ports offloaded, at most BLOCK_MAX_FRAC blocked by the
     governor, at most MAX_DIRECTIVES directives applied per round
  V5 the controller sets all timers (TTL, pardon, meter cap); the governor cannot
  V6 unknown action / unknown IP / malformed directive -> rejected
"""
import csv
import ipaddress
import json
import os
import time
from collections import defaultdict

GOV_ON = os.environ.get("SDN_GOV", "0") == "1"
GOV_DIR = os.environ.get("SDN_GOV_DIR", ".")
GOV_PERIOD = float(os.environ.get("SDN_GOV_PERIOD", "30"))
OFF_TTL = int(os.environ.get("SDN_GOV_OFF_TTL", "60"))
OFF_PPS = int(os.environ.get("SDN_GOV_OFF_PPS", "100"))
PARDON_S = float(os.environ.get("SDN_GOV_PARDON_S", "60"))
OFF_MAX_FRAC = float(os.environ.get("SDN_GOV_OFF_MAX", "0.35"))
BLOCK_MAX_FRAC = float(os.environ.get("SDN_GOV_BLOCK_MAX", "0.10"))
MAX_DIRECTIVES = int(os.environ.get("SDN_GOV_MAX_DIR", "40"))
# M scaled with the network: M = max(MAX_DIRECTIVES, floor(phi * |P|)), so one round can fill the whole offload budget
# (40 at 96 devices, i.e. unchanged; 67 at 192). With a fixed M = 40 a legitimate crowd larger than 40 devices is
# never fully offloaded (scaling study)
MAX_DIR_SCALE = os.environ.get("SDN_GOV_MAX_DIR_SCALE", "0") == "1"
BOUNDED = os.environ.get("SDN_GOV_BOUNDED", "1") == "1"      # 0 = ablation: verifier only checks V6
V7 = os.environ.get("SDN_GOV_V7", "0") == "1"
# V8 (ingress pinning): on edge switches other than the device's own, the fast-path rule also matches
# in_port = uplink, so a device elsewhere that spoofs an offloaded address cannot enter the fast path
# unmetered (0 = ablation, the pre-V8 rule set)
V8 = os.environ.get("SDN_GOV_V8", "1") == "1"
# V9 (release budget): pardoned + offloaded devices together stay within OFF_MAX_FRAC of device ports
V9 = os.environ.get("SDN_GOV_V9", "1") == "1"
# V10 (reverse-path pinning): the reply rule of an offloaded device (ipv4_dst = ip(k)) is installed only on the
# device's home switch, matching in_port = uplink, and on the core switch. Without V10 it was installed on every
# edge switch with no in_port match, so a device WITHOUT a fast path could send to ip(k) - with any source
# address - and skip PPO and the controller on its own switch (0 = the V7.2 rule set used in Sections 7.1-7.8)
# V10 modes: "0" off, "1" strict (no reply rule on other edge switches; reply rule on the home switch only from the
# uplink), "src" source-pinned (reply rules match ipv4_src in the local switch's own /24, at one priority below the
# forward rules, so a random- or foreign-source flood misses them and reaches the controller, while replies from
# local devices keep the fast path)
V10MODE = os.environ.get("SDN_GOV_V10", "0")
V10 = V10MODE == "1"
V10S = V10MODE in ("src", "pin")   # "src" = first build (subnet bug, superseded), "pin" = fixed
OFF_LIFE = int(os.environ.get("SDN_GOV_OFF_LIFE", "300"))   # V7: longest life of one verified offload
PRIO_OFF = 11
OFF_TABLE = 1
OFF_COOKIE = 0x0FF0000000000000
STATE_TOP = 40


class GovernanceMixin:
    # ------------------------------------------------------------------ setup
    def _gov_init(self):
        self.gov_pin = defaultdict(int)
        self.gov_spoof = defaultdict(int)
        self.gov_dst = defaultdict(set)
        self.gov_last = time.time()
        self.gov_seq = 0
        self.gov_done_seq = 0
        self.offloaded = {}          # (dpid, port) -> expiry
        self.pardon = {}             # (dpid, port) -> expiry
        self.gov_blocked = set()
        self.gov_rx0 = {}            # (dpid, port) -> rx counter at the start of the window
        self.gov_stress = 0
        self.off_tab = {}
        self.off_since = {}          # device -> time of the (verified) grant            # dpid -> set of (net, mask, out) installed in table 1
        if not GOV_ON:
            return
        self.gout = open(os.path.join(GOV_DIR, "gov_actions.csv"), "w", newline="")
        self.gw = csv.writer(self.gout)
        self.gw.writerow(["ts", "seq", "action", "ip", "dpid", "port", "verdict", "rule"])
        self.logger.info("governance on: period=%ss bounded=%s v7=%s v8=%s v10=%s", GOV_PERIOD, BOUNDED, V7, V8, V10MODE)

    # ------------------------------------------------------------------ per second
    def _gov_tick(self, now, backlog):
        """Called once per second BEFORE the per-second counters are cleared."""
        if not GOV_ON:
            return
        for k, n in self.port_pin.items():
            self.gov_pin[k] += n
        for k, n in self.port_spoof.items():
            self.gov_spoof[k] += n
        for k, s in self.port_dst.items():
            if len(self.gov_dst[k]) < 256:
                self.gov_dst[k].update(list(s)[:256])
        for k, t in list(self.offloaded.items()):
            if now >= t:
                pin = self.gov_pin.get(k, 0)
                sp = self.gov_spoof.get(k, 0) / pin if pin else 0.0
                if V7 and BOUNDED and now - self.off_since.get(k, now) < OFF_LIFE and sp < 0.05:
                    # V7: a verified offload is not ended by the advisor's silence either - the controller
                    # keeps it (same caps) while the evidence stays clean, up to OFF_LIFE after the grant
                    self._gov_offload(k, now)
                    self._gov_log(now, "renew", self.port_ip.get(k), k, "ok", "V7 sticky")
                    continue
                # explicit delete as well as the hard timeout: the budget slot is reused only after the rule is gone
                self._gov_revoke(k)
                self._gov_log(now, "expire", self.port_ip.get(k), k, "ok", "ttl")
        # consult the governor every GOV_PERIOD s, or early (>= 10 s after the last round) when the
        # controller queue has been near saturation for 3 s
        self.gov_stress = self.gov_stress + 1 if backlog >= 100 else 0
        if now - self.gov_last >= GOV_PERIOD or (self.gov_stress >= 3 and now - self.gov_last >= 10):
            self._gov_dump(now, backlog)
            self.gov_rx0 = dict(self.port_rx_now)
            self.gov_last = now
            self.gov_pin.clear(); self.gov_spoof.clear(); self.gov_dst.clear()
        self._gov_read(now)

    def _gov_pardoned(self, k, now, spoof_share):
        return now < self.pardon.get(k, 0) and spoof_share < 0.05

    # ------------------------------------------------------------------ snapshot for the governor
    def _gov_dump(self, now, backlog):
        ports = self._host_ports()
        win = max(1.0, now - self.gov_last)
        rows = []
        for k in ports:
            pin = self.gov_pin.get(k, 0)
            rows.append(dict(ip=self.port_ip.get(k), switch=k[0], port=k[1],
                             new_flows_per_s=round(pin / win, 1),
                             foreign_source_share=round(self.gov_spoof.get(k, 0) / pin, 2) if pin else 0.0,
                             distinct_destinations=len(self.gov_dst.get(k, ())),
                             data_packets_per_s=round(max(0, self.port_rx_now.get(k, 0)
                                                         - self.gov_rx0.get(k, self.port_rx_now.get(k, 0))) / win, 1),
                             fast_loop_action=["allow", "limit", "block"][self.port_act[k]],
                             offloaded=k in self.offloaded))
        rows.sort(key=lambda r: -r["new_flows_per_s"])
        shown = [r for i, r in enumerate(rows) if i < STATE_TOP or r["fast_loop_action"] != "allow"
                 or r["offloaded"]]
        tot = sum(self.gov_pin.get(k, 0) for k in ports) / win
        self.gov_seq += 1
        st = dict(seq=self.gov_seq, time=round(now, 1), window_s=round(win),
                  controller=dict(queue_now=backlog, queue_capacity=128,
                                  device_new_flows_per_s=round(tot, 1), approx_capacity_per_s=400),
                  devices_total=len(ports),
                  devices_limited=sum(1 for k in ports if self.port_act[k] == 1),
                  devices_blocked=sum(1 for k in ports if self.port_act[k] == 2),
                  devices_offloaded=len(self.offloaded),
                  budgets=dict(max_offloaded=int(OFF_MAX_FRAC * len(ports)),
                               max_governor_blocks=int(BLOCK_MAX_FRAC * len(ports)),
                               max_directives=self._gov_max_dir(len(ports))),
                  devices=shown)
        tmp = os.path.join(GOV_DIR, ".gov_state.tmp")
        with open(tmp, "w") as f:
            json.dump(st, f)
        os.replace(tmp, os.path.join(GOV_DIR, "gov_state.json"))

    # ------------------------------------------------------------------ directives
    def _gov_read(self, now):
        path = os.path.join(GOV_DIR, "gov_directives.json")
        try:
            with open(path) as f:
                d = json.load(f)
        except Exception:
            return
        seq = d.get("seq", 0) if isinstance(d, dict) else 0
        if not isinstance(seq, int) or seq <= self.gov_done_seq:
            return
        self.gov_done_seq = seq
        acts = d.get("actions", []) if isinstance(d, dict) else []
        if not isinstance(acts, list):
            acts = []
        ports = self._host_ports()
        # map IPs to device ports only (a switch link may have "learned" some host's IP first)
        by_ip = {self.port_ip.get(k): k for k in ports if self.port_ip.get(k)}
        n_ok = 0
        self._routes_cache = None
        for a in acts[:200]:
            if not isinstance(a, dict):
                self._gov_log(now, "?", None, None, "reject", "V6 malformed"); continue
            typ, ip = str(a.get("type", "")).lower(), str(a.get("ip", ""))
            k = by_ip.get(ip)
            verdict, rule = self._gov_verify(typ, ip, k, ports, n_ok)
            self._gov_log(now, typ, ip, k, verdict, rule)
            if verdict != "ok":
                continue
            n_ok += 1
            if typ == "offload":
                self._gov_offload(k, now)
            elif typ == "revoke":
                self._gov_revoke(k)
            elif typ == "release":
                self.pardon[k] = now + PARDON_S
                if self.port_act[k] != 0:
                    self._apply(k, 0, now, "gov-release")
            elif typ == "block":
                self.gov_blocked.add(k)
                self.hold[k] = now + 3600
                self._apply(k, 2, now, "gov-block")
        self.gout.flush()

    def _gov_verify(self, typ, ip, k, ports, n_ok):
        if typ not in ("offload", "release", "block", "revoke"):
            return "reject", "V6 unknown action"
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return "reject", "V6 bad ip"
        if k is None:
            return "reject", "V6 unknown ip"
        pin = self.gov_pin.get(k, 0) + self.port_pin.get(k, 0)
        sp = (self.gov_spoof.get(k, 0) + self.port_spoof.get(k, 0)) / pin if pin else 0.0
        if typ == "revoke":
            if k not in self.offloaded:
                return "reject", "V6 not offloaded"
            # V7 (evidence-gated revocation): taking trust away is itself an attack surface (denial of
            # trust: an injected notice can make the advisor revoke a legitimate crowd), so a revocation
            # needs the same kind of evidence as the grant check: foreign sources seen on the port
            if BOUNDED and V7 and sp < 0.05:
                return "reject", "V7 no evidence against the device"
            return "ok", "V6 passed"
        if not BOUNDED:
            return "ok", "unbounded"
        if not self._is_host_port(k) or ip in self.__class__._protect():
            return "reject", "V1 not a device port"
        if n_ok >= self._gov_max_dir(len(self._host_ports())):
            return "reject", "V4 directive budget"
        if typ in ("offload", "release") and sp >= 0.05:
            return "reject", "V2 foreign sources seen"
        if typ == "block" and sp < 0.5:
            return "reject", "V3 no spoofing evidence"
        held = set(self.offloaded)
        if V9:
            held |= {q for q, t in self.pardon.items() if t > time.time()}
        if typ == "offload" and k not in held and len(held) >= int(OFF_MAX_FRAC * len(ports)):
            return "reject", "V4 offload budget"
        if typ == "release" and V9:
            # V9 (release budget): a pardoned device leaves the fast loop, so pardons share the offload slots
            now = time.time()
            live = {q for q, t in self.pardon.items() if t > now}
            if k not in live and len(live | set(self.offloaded)) >= int(OFF_MAX_FRAC * len(ports)):
                return "reject", "V9 release budget"
        if typ == "block" and len(self.gov_blocked) >= max(1, int(BLOCK_MAX_FRAC * len(ports))):
            return "reject", "V4 block budget"
        return "ok", "V1-V6 passed"

    @staticmethod
    def _protect():
        return set(os.environ.get("SDN_PROTECT_IP", "10.0.0.254").split(","))

    def _gov_log(self, now, typ, ip, k, verdict, rule):
        if GOV_ON:
            self.gw.writerow([round(now, 3), self.gov_done_seq, typ, ip,
                              k[0] if k else "", k[1] if k else "", verdict, rule])

    # ------------------------------------------------------------------ offload = trusted fast path
    def _routes(self):
        """switch -> list of (ipv4 prefix, out_port). Aggregates /24s whose hosts share an out port."""
        hosts = []                                   # (ip, mac, home_dpid, home_port)
        for k, ip in self.port_ip.items():
            macs = self.port_macs.get(k, ())
            if k in self.trunk or len(macs) != 1:
                continue
            hosts.append((ip, next(iter(macs)), k[0], k[1]))
        routes = {}
        for s in list(self.datapaths):
            trunks = [k[1] for k in self.trunk if k[0] == s]
            per = {}
            for ip, mac, hd, hp in hosts:
                if hd == s:
                    out = hp
                else:
                    out = self.mac_to_port.get(s, {}).get(mac)
                    if out is None and len(trunks) == 1:
                        out = trunks[0]              # edge switch: everything non-local goes up
                if out is not None:
                    per[ip] = out
            groups = defaultdict(set)
            for ip, out in per.items():
                groups[ipaddress.ip_network(ip + "/24", strict=False)].add(out)
            r = []
            for net, outs in groups.items():
                if len(outs) == 1:
                    r.append((str(net.network_address), "255.255.255.0", outs.pop()))
                else:
                    r += [(ip, "255.255.255.255", out) for ip, out in per.items()
                          if ipaddress.ip_address(ip) in net]
            routes[s] = r
        return routes

    def _gov_table1(self):
        """Bring table 1 (shared destination routes for offloaded traffic) up to date: diff only."""
        if self._routes_cache is None:
            self._routes_cache = self._routes()
        for s, rules in self._routes_cache.items():
            dp = self.datapaths.get(s)
            if dp is None:
                continue
            p, o = dp.ofproto_parser, dp.ofproto
            have = self.off_tab.get(s)
            if have is None:
                # table-1 miss: to the controller (a destination not routed yet; see _packet_in)
                dp.send_msg(p.OFPFlowMod(datapath=dp, table_id=OFF_TABLE, priority=0, match=p.OFPMatch(),
                                         instructions=[p.OFPInstructionActions(o.OFPIT_APPLY_ACTIONS,
                                             [p.OFPActionOutput(o.OFPP_CONTROLLER, o.OFPCML_NO_BUFFER)])]))
                have = self.off_tab[s] = set()
            want = set(rules)
            for net, mask, out in want - have:
                dp.send_msg(p.OFPFlowMod(datapath=dp, table_id=OFF_TABLE, priority=PRIO_OFF,
                                         match=p.OFPMatch(eth_type=0x0800, ipv4_dst=(net, mask)),
                                         instructions=[p.OFPInstructionActions(o.OFPIT_APPLY_ACTIONS,
                                                                               [p.OFPActionOutput(out)])]))
                self.fmod[s] += 1
            for net, mask, out in have - want:
                if not any(n == net and m == mask for n, m, _ in want):
                    dp.send_msg(p.OFPFlowMod(datapath=dp, table_id=OFF_TABLE, command=o.OFPFC_DELETE_STRICT,
                                             priority=PRIO_OFF, match=p.OFPMatch(eth_type=0x0800, ipv4_dst=(net, mask)),
                                             out_port=o.OFPP_ANY, out_group=o.OFPG_ANY))
            self.off_tab[s] = want

    def _gov_max_dir(self, n_ports):
        return max(MAX_DIRECTIVES, int(OFF_MAX_FRAC * n_ports)) if MAX_DIR_SCALE else MAX_DIRECTIVES

    def _gov_subnet(self, s):
        """The /24 of the devices attached to edge switch s: the most common /24 among the addresses learned on its
        DEVICE ports. Trunk ports are skipped - an uplink also 'learns' the source of the first packet that arrived on
        it, which belongs to another switch (that bug made the reply rules of some switches match nothing).
        Falls back to the testbed plan 10.<s//250>.<s%250>.0/24."""
        votes = defaultdict(int)
        for (ps, pp), ip in self.port_ip.items():
            if ps == s and ip and (ps, pp) not in self.trunk and pp != 1:
                votes[ip.rsplit(".", 1)[0] + ".0"] += 1
        if votes:
            return (max(votes, key=votes.get), "255.255.255.0")
        return ("10.%d.%d.0" % (s // 250, s % 250), "255.255.255.0")

    def _gov_offload(self, k, now):
        """One table-0 rule per switch steers the device's IPv4 traffic into table 1. Renewal re-adds the
        same rules (an OpenFlow ADD of an identical entry restarts its hard timeout)."""
        ip = self.port_ip[k]
        hd, hp = k
        renew = k in self.offloaded
        self.offloaded[k] = now + OFF_TTL
        self.off_since.setdefault(k, now)
        self._gov_table1()
        host_ports = self._host_ports()
        for s in list(self.datapaths):
            dp = self.datapaths.get(s)
            if dp is None:
                continue
            p, o = dp.ofproto_parser, dp.ofproto
            goto = p.OFPInstructionGotoTable(OFF_TABLE)
            if s == hd:
                if not renew:
                    cap = OFF_PPS if BOUNDED else 100000      # unbounded ablation: no rate cap on the fast path
                    for mid, rate in ((2000 + hp, cap), (3000 + hp, 2 * cap)):
                        dp.send_msg(p.OFPMeterMod(dp, command=o.OFPMC_ADD, flags=o.OFPMF_PKTPS, meter_id=mid,
                                                  bands=[p.OFPMeterBandDrop(rate=rate, burst_size=rate)]))
                fwd = (p.OFPMatch(in_port=hp, eth_type=0x0800, ipv4_src=ip), [p.OFPInstructionMeter(2000 + hp), goto])
                # replies to the device (e.g. from the many destinations it contacts) are delivered
                # directly, capped at 2 x OFF_PPS, instead of each new pair reaching the controller
                deliver = [p.OFPInstructionMeter(3000 + hp),
                           p.OFPInstructionActions(o.OFPIT_APPLY_ACTIONS, [p.OFPActionOutput(hp)])]
                if V10S:
                    rev = [(p.OFPMatch(in_port=1, eth_type=0x0800, ipv4_dst=ip), deliver),
                           (p.OFPMatch(eth_type=0x0800, ipv4_src=self._gov_subnet(s), ipv4_dst=ip), deliver)]
                else:
                    rev = (p.OFPMatch(in_port=1, eth_type=0x0800, ipv4_dst=ip) if V10 else p.OFPMatch(eth_type=0x0800, ipv4_dst=ip),
                           deliver)
            elif V8 and any(ps == s for ps, _ in host_ports):
                # V8: another edge switch - only traffic arriving from the uplink (port 1) may take the fast path
                fwd = (p.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src=ip), [goto])
                # V10: no reply rule on another edge switch (a packet to ip(k) from a device there takes the
                # ordinary path: PacketIn, PPO, reactive flow)
                if V10S:
                    rev = (p.OFPMatch(eth_type=0x0800, ipv4_src=self._gov_subnet(s), ipv4_dst=ip), [goto])
                else:
                    rev = None if V10 else (p.OFPMatch(eth_type=0x0800, ipv4_dst=ip), [goto])
            else:
                fwd = (p.OFPMatch(eth_type=0x0800, ipv4_src=ip), [goto])
                rev = (p.OFPMatch(eth_type=0x0800, ipv4_dst=ip), [goto])
            # V10b priorities: forward rules above reply rules (a packet from an offloaded port always takes its own
            # forward meter, also when it is addressed to another offloaded device), and reply rules above the reactive
            # flows (PRIO_FLOW = 10), so a reply is always metered at delivery
            rules = [(fwd, PRIO_OFF + 1 if V10S else PRIO_OFF)]
            if rev is not None:
                # V10src: reply rules one priority below forward rules, so a packet from an offloaded port always
                # takes its own forward meter even when it is addressed to another offloaded device
                for r in (rev if isinstance(rev, list) else [rev]):
                    rules.append((r, PRIO_OFF))
            for (match, inst), prio in rules:
                dp.send_msg(p.OFPFlowMod(datapath=dp, cookie=OFF_COOKIE | (hd << 16) | hp, priority=prio,
                                         match=match, instructions=inst, hard_timeout=OFF_TTL))
                self.fmod[s] += 1

    def _gov_revoke(self, k):
        """Remove the fast path of one device on every switch (cookie match) and its meters."""
        hd, hp = k
        self.offloaded.pop(k, None)
        self.off_since.pop(k, None)
        for s in list(self.datapaths):
            dp = self.datapaths.get(s)
            if dp is None:
                continue
            p, o = dp.ofproto_parser, dp.ofproto
            dp.send_msg(p.OFPFlowMod(datapath=dp, table_id=0, command=o.OFPFC_DELETE,
                                     cookie=OFF_COOKIE | (hd << 16) | hp, cookie_mask=0xFFFFFFFFFFFFFFFF,
                                     out_port=o.OFPP_ANY, out_group=o.OFPG_ANY, match=p.OFPMatch()))
            if s == hd:
                for mid in (2000 + hp, 3000 + hp):
                    dp.send_msg(p.OFPMeterMod(dp, command=o.OFPMC_DELETE, meter_id=mid))
