"""
SDN-IoT controller with control-plane telemetry and selectable baseline defenses.

Forwarding: reactive L3-aware switching (in_port, eth_dst, ipv4_src, ipv4_dst):
every new IP source causes a table miss -> PacketIn (exposes saturation attacks).

Telemetry, 1 Hz, $SDN_METRICS (default metrics_ctl.csv):
  ts, dpid, packet_in, flow_mod, backlog, flow_count, rx_pkts, tx_pkts, ctl_proc_ms, blocked_ports
Defense actions, $SDN_ACTIONS (default actions.csv):
  ts, dpid, port, action, reason

Defenses ($SDN_DEFENSE):
  none       no mitigation (baseline)
  threshold  per-port PacketIn rate > $SDN_TH msg/s on a host-facing port
             -> drop rule on that port for $SDN_BLOCK_S s
             (typical static-threshold SDN IDS baseline)
  rule       strong hand-written per-port heuristic: block ports that send spoofed sources or
             scan many destinations, rate-limit heavy ports (actions held 10 s)
  ppo        trained PPO policy (ppo/ppo_policy.npz) decides allow / limit / block per host
             port every second from the same per-port features
  meter      OpenFlow meter on the table-miss rule caps PacketIn per switch at
             $SDN_METER_PPS pkt/s (switch-side PacketIn rate limiting, in the
             spirit of AVANT-GUARD / FloodGuard: protects the controller, but
             also drops benign new flows -> collateral damage is measurable)
"""
import csv
import json
import os

import numpy as np
import time
from collections import defaultdict

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.lib.packet import packet, ethernet, ether_types, ipv4
from os_ken.ofproto import ofproto_v1_3

from governance import GovernanceMixin

IDLE_TIMEOUT = int(os.environ.get("SDN_IDLE_TIMEOUT", "10"))
FLOW_TABLE_LIMIT = int(os.environ.get("SDN_FLOW_LIMIT", "1000"))
DEFENSE = os.environ.get("SDN_DEFENSE", "none")
TH = float(os.environ.get("SDN_TH", "50"))
BLOCK_S = int(os.environ.get("SDN_BLOCK_S", "10"))
PPO_HOLD_S = float(os.environ.get("SDN_PPO_HOLD_S", "10"))  # minimum time a PPO restriction is kept
WARMUP_S = float(os.environ.get("SDN_WARMUP_S", "15"))   # no per-port decisions in a switch's first 15 s
METER_PPS = int(os.environ.get("SDN_METER_PPS", "200"))
LIMIT_PPS = int(os.environ.get("SDN_LIMIT_PPS", "10"))
PPO_PATH = os.environ.get("SDN_PPO_POLICY", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                         "ppo", "ppo_policy.npz"))
MU_EST = 600.0
PROTECT = set(os.environ.get("SDN_PROTECT_IP", "10.0.0.254").split(","))   # servers are never agents                      # effective controller capacity used to normalize features
PRIO_FLOW, PRIO_LIMIT, PRIO_BLOCK = 10, 5, 100
ALLOW, LIMIT, BLOCK = 0, 1, 2


class TelemetrySwitch(GovernanceMixin, app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.mac_to_port = {}
        self.datapaths = {}
        self.pin = defaultdict(int)
        self.fmod = defaultdict(int)
        self.proc_ms = defaultdict(list)
        self.flow_count = defaultdict(int)
        self.port_rx = defaultdict(int)
        self.port_tx = defaultdict(int)
        self.prev_rx = defaultdict(int)
        self.prev_tx = defaultdict(int)
        self.port_pin = defaultdict(int)           # (dpid, port) -> PacketIn this second
        self.port_macs = defaultdict(set)          # (dpid, port) -> source MACs seen
        self.dp_since = {}                         # dpid -> time the switch connected
        self.trunk = set()                         # switch-to-switch ports (never restricted)
        self.mac_home = {}                         # MAC -> (dpid, port) where it was first seen
        self.blocked = {}                          # (dpid, port) -> unblock time
        self.port_src = defaultdict(set)           # (dpid, port) -> IPv4 sources this second
        self.port_spoof = defaultdict(int)         # (dpid, port) -> PacketIns with foreign source
        self.port_dst = defaultdict(set)           # (dpid, port) -> IPv4 destinations this second
        self.port_ip = {}                          # (dpid, port) -> the device's own IPv4 (first seen)
        self.port_rx_now = {}                      # (dpid, port) -> rx packet counter
        self.port_rx_prev = {}
        self.port_act = defaultdict(int)           # (dpid, port) -> current action
        self.hold = {}                             # (dpid, port) -> time until which action is held
        self.policy = None
        # published-method baselines (see baselines/):
        #  rf      - Random-Forest port classifier (trees exported to numpy by baselines/train_rf.py)
        #  entropy - destination-entropy detector of Mousavi & St-Hilaire (2015): entropy of the destination
        #            addresses in windows of ENT_W PacketIns; attack when ENT_K consecutive windows fall below a
        #            threshold calibrated on pre-attack traffic (mean - 3 sd). The paper specifies detection
        #            only; as mitigation we rate-limit ports sending >= ENT_PIN PacketIns/s while flagged.
        self.rf = None
        if DEFENSE == "rf":
            self.rf = dict(np.load(os.environ.get("SDN_RF_MODEL", os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "baselines", "rf_model.npz"))))
        self.ent_buf, self.ent_cal, self.ent_low, self.ent_thr, self.ent_t0 = [], [], 0, None, None
        self.ent_flag_until = 0.0
        #  llmport - port-level monitoring + zero-training LLM of Swileh & Zhang (2026): an external process
        #            (baselines/llmport.py) classifies each port's 10-s counter window with few-shot prompts;
        #            flagged ports get a drop rule, re-enabled 30 s after the last flag
        self.port_cnt = {}
        self.llm_seen = 0
        if DEFENSE == "ppo":
            d = np.load(PPO_PATH)
            self.policy = [(d["aW%d" % i], d["ab%d" % i]) for i in range(3)]
        self.out = open(os.environ.get("SDN_METRICS", "metrics_ctl.csv"), "w", newline="")
        self.w = csv.writer(self.out)
        self.w.writerow(["ts", "dpid", "packet_in", "flow_mod", "backlog", "flow_count",
                         "rx_pkts", "tx_pkts", "ctl_proc_ms", "blocked_ports"])
        self.aout = open(os.environ.get("SDN_ACTIONS", "actions.csv"), "w", newline="")
        self.aw = csv.writer(self.aout)
        self.aw.writerow(["ts", "dpid", "port", "action", "reason"])
        self.logger.info("defense=%s TH=%s METER_PPS=%s", DEFENSE, TH, METER_PPS)
        self._gov_init()
        hub.spawn(self._stats_loop)
        hub.spawn(self._report_loop)

    # ---------- switch lifecycle ----------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif dp.id in self.datapaths:
            del self.datapaths[dp.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features(self, ev):
        dp = ev.msg.datapath
        p, o = dp.ofproto_parser, dp.ofproto
        to_ctl = [p.OFPActionOutput(o.OFPP_CONTROLLER, o.OFPCML_NO_BUFFER)]
        if DEFENSE == "meter":
            dp.send_msg(p.OFPMeterMod(dp, command=o.OFPMC_ADD, flags=o.OFPMF_PKTPS, meter_id=1,
                                      bands=[p.OFPMeterBandDrop(rate=METER_PPS, burst_size=METER_PPS // 4)]))
            inst = [p.OFPInstructionMeter(1), p.OFPInstructionActions(o.OFPIT_APPLY_ACTIONS, to_ctl)]
            dp.send_msg(p.OFPFlowMod(datapath=dp, priority=0, match=p.OFPMatch(), instructions=inst))
            self.fmod[dp.id] += 1
        else:
            self.add_flow(dp, 0, p.OFPMatch(), to_ctl, idle=0)
        self.logger.info("switch connected dpid=%s", dp.id)
        self.dp_since[dp.id] = time.time()

    def add_flow(self, dp, prio, match, actions, idle=IDLE_TIMEOUT, hard=0, table=0):
        p = dp.ofproto_parser
        inst = [p.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        dp.send_msg(p.OFPFlowMod(datapath=dp, table_id=table, priority=prio, match=match, instructions=inst,
                                 idle_timeout=idle, hard_timeout=hard))
        self.fmod[dp.id] += 1

    # ---------- reactive forwarding ----------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        t0 = time.perf_counter()
        msg = ev.msg
        dp = msg.datapath
        p, o = dp.ofproto_parser, dp.ofproto
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
            return
        self.pin[dp.id] += 1
        self.port_pin[(dp.id, in_port)] += 1
        self.port_macs[(dp.id, in_port)].add(eth.src)
        # a MAC is "at home" on the first switch port where it was seen (a host's first frame always
        # reaches its own edge switch first); seeing it later on another switch marks that port as a
        # switch-to-switch link, which no per-device defense may ever restrict
        home = self.mac_home.setdefault(eth.src, (dp.id, in_port))
        if home[0] != dp.id:
            self.trunk.add((dp.id, in_port))
        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4:
            key = (dp.id, in_port)
            if os.environ.get("SDN_DEBUG_PIN"): self.logger.info("PIN %.1f s%s p%s t%s %s>%s pr%s", time.time(), dp.id, in_port, msg.table_id, ip4.src, ip4.dst, ip4.proto)
            self.port_ip.setdefault(key, ip4.src)
            if ip4.src != self.port_ip[key]:
                self.port_spoof[key] += 1
                if os.environ.get("SDN_DEBUG_SPOOF"): self.logger.info("SPOOF %s %s learned=%s src=%s dst=%s proto=%s", time.time(), key, self.port_ip[key], ip4.src, ip4.dst, ip4.proto)
            self.port_dst[key].add(ip4.dst)
            if DEFENSE == "entropy":
                self.ent_buf.append(ip4.dst)
        if (dp.id, in_port) in self.blocked:
            return
        table = self.mac_to_port.setdefault(dp.id, {})
        table[eth.src] = in_port
        out_port = table.get(eth.dst, o.OFPP_FLOOD)
        actions = [p.OFPActionOutput(out_port)]
        if out_port != o.OFPP_FLOOD and self.flow_count[dp.id] < FLOW_TABLE_LIMIT:
            ip = pkt.get_protocol(ipv4.ipv4)
            if ip:
                match = p.OFPMatch(in_port=in_port, eth_type=0x0800, eth_dst=eth.dst,
                                   ipv4_src=ip.src, ipv4_dst=ip.dst)
            else:
                match = p.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            # a miss in table 1 (offloaded traffic, destination without a shared route) is learned there
            self.add_flow(dp, PRIO_FLOW, match, actions, table=msg.table_id if msg.table_id == 1 else 0)
        data = msg.data if msg.buffer_id == o.OFP_NO_BUFFER else None
        dp.send_msg(p.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data))
        self.proc_ms[dp.id].append((time.perf_counter() - t0) * 1000)

    # ---------- threshold defense ----------
    def _threshold_step(self, now):
        for key, until in list(self.blocked.items()):
            if now >= until:
                del self.blocked[key]
                self.aw.writerow([round(now, 3), key[0], key[1], "unblock", "timeout"])
        for (dpid, port), n in self.port_pin.items():
            host_port = self._is_host_port((dpid, port), now)        # one device behind it, not the broker
            if n > TH and host_port and (dpid, port) not in self.blocked and dpid in self.datapaths:
                dp = self.datapaths[dpid]
                p = dp.ofproto_parser
                self.add_flow(dp, 100, p.OFPMatch(in_port=port), [], idle=0, hard=BLOCK_S)
                self.blocked[(dpid, port)] = now + BLOCK_S
                self.aw.writerow([round(now, 3), dpid, port, "block", "pin=%d" % n])

    # ---------- per-port defenses (rule / ppo) ----------
    def _is_host_port(self, k, now=None):
        """A port is treated as a single-device (host) port only if it never carried > 2 MACs, its
        switch has been up for WARMUP_S (so switch-to-switch links have had time to show many MACs),
        it is not the uplink (port 1), and the device behind it is not a protected server (broker)."""
        macs = self.port_macs.get(k, ())
        if len(macs) > 2:
            self.trunk.add(k)
        now = now or time.time()
        return (k not in self.trunk and k[1] != 1 and k[0] in self.datapaths
                and now - self.dp_since.get(k[0], now) >= WARMUP_S
                and self.port_ip.get(k) not in PROTECT)

    def _host_ports(self):
        now = time.time()
        return [k for k in list(self.port_macs) if self._is_host_port(k, now)]

    def _port_features(self, ports, backlog):
        per = np.zeros((len(ports), 7), np.float64)
        for i, k in enumerate(ports):
            pin = self.port_pin.get(k, 0)
            rx = self.port_rx_now.get(k, 0) - self.port_rx_prev.get(k, self.port_rx_now.get(k, 0))
            per[i, 0] = np.log1p(pin) / 7
            per[i, 1] = self.port_spoof.get(k, 0) / pin if pin else 0.0
            per[i, 2] = np.log1p(len(self.port_dst.get(k, ()))) / 4
            per[i, 3] = min(np.log1p(max(rx, 0)) / 7, 1.5)    # stay inside the trained feature range
            per[i, 4 + self.port_act[k]] = 1.0
        tot = sum(self.port_pin.get(k, 0) for k in ports)
        g = np.array([backlog / 128.0, tot / MU_EST, 0.0])
        return per, g

    def _rule_decide(self, per):
        pin = np.expm1(per[:, 0] * 7)
        ndst = np.expm1(per[:, 2] * 4)
        a = np.zeros(len(per), int)
        a[pin > 20] = LIMIT
        a[(per[:, 1] > 0.5) & (pin > 5)] = BLOCK
        a[ndst > 10] = BLOCK
        return a

    def _rf_decide(self, per, g):
        X = np.concatenate([per[:, :4], np.repeat(g[None, :2], len(per), 0)], 1)
        F, T, L, R, P = (self.rf[k] for k in ("feature", "threshold", "left", "right", "p1"))
        n, rows = len(X), np.arange(len(X))
        prob = np.zeros(n)
        for t in range(len(F)):
            idx = np.zeros(n, int)
            for _ in range(64):
                f = F[t][idx]
                leaf = f < 0
                if leaf.all():
                    break
                go = X[rows, np.where(leaf, 0, f)] <= T[t][idx]
                idx = np.where(leaf, idx, np.where(go, L[t][idx], R[t][idx]))
            prob += P[t][idx]
        prob /= len(F)
        if "gb_feature" in self.rf:                       # hybrid: soft vote with the boosted trees
            F, T, L, R, V = (self.rf[k] for k in ("gb_feature", "gb_threshold", "gb_left", "gb_right", "gb_value"))
            raw = np.full(n, float(self.rf["gb_init"]))
            for t in range(len(F)):
                idx = np.zeros(n, int)
                for _ in range(64):
                    f = F[t][idx]
                    leaf = f < 0
                    if leaf.all():
                        break
                    go = X[rows, np.where(leaf, 0, f)] <= T[t][idx]
                    idx = np.where(leaf, idx, np.where(go, L[t][idx], R[t][idx]))
                raw += float(self.rf["gb_lr"]) * V[t][idx]
            prob = (prob + 1.0 / (1.0 + np.exp(-raw))) / 2
        return np.where(prob > 0.5, BLOCK, ALLOW)

    def _llmport_step(self, now):
        d = os.path.dirname(os.environ.get("SDN_METRICS", "metrics_ctl.csv")) or "."
        ports = self._host_ports()
        snap = dict(t=now, ports=[[k[0], k[1]] + list(self.port_cnt.get(k, (0, 0, 0, 0))) for k in ports])
        tmp = os.path.join(d, ".port_counters.tmp")
        with open(tmp, "w") as f:
            json.dump(snap, f)
        os.replace(tmp, os.path.join(d, "port_counters.json"))
        try:
            dr = json.load(open(os.path.join(d, "llmport_flags.json")))
        except Exception:
            dr = {}
        for key, ts in dr.get("flags", {}).items():
            dpid, port = (int(x) for x in key.split(":"))
            k = (dpid, port)
            if k not in ports:
                continue
            if ts > self.hold.get(k, 0) - 30:
                self.hold[k] = ts + 30                    # re-enable 30 s after the last flag
            if self.port_act[k] != BLOCK and now < self.hold[k]:
                self._apply(k, BLOCK, now, "llmport")
        for k in ports:
            if self.port_act[k] == BLOCK and now >= self.hold.get(k, 0):
                self._apply(k, ALLOW, now, "llmport")

    def _entropy_step(self, now):
        ENT_W, ENT_K, ENT_PIN, CAL_S = 50, 5, 10, float(os.environ.get("SDN_ENT_CAL_S", "40"))
        if self.ent_t0 is None:
            if not self.ent_buf:
                return                      # calibration starts with the first device traffic
            self.ent_t0 = now
        buf, self.ent_buf = self.ent_buf, []
        for i in range(0, len(buf) - ENT_W + 1, ENT_W):
            w = buf[i:i + ENT_W]
            _, c = np.unique(w, return_counts=True)
            pr = c / c.sum()
            h = float(-(pr * np.log(pr)).sum() / np.log(ENT_W))      # normalised to [0, 1]
            if now - self.ent_t0 < CAL_S:
                self.ent_cal.append(h)
                continue
            if self.ent_thr is None:
                cal = np.array(self.ent_cal) if self.ent_cal else np.array([1.0])
                self.ent_thr = float(cal.mean() - 3 * cal.std())
                self.logger.info("entropy threshold %.3f from %d windows", self.ent_thr, len(cal))
            self.ent_low = self.ent_low + 1 if h < self.ent_thr else 0
            if self.ent_low >= ENT_K:
                self.ent_flag_until = now + BLOCK_S
        ports = self._host_ports()
        for k in ports:
            if now < self.ent_flag_until and self.port_pin.get(k, 0) >= ENT_PIN and self.port_act[k] == ALLOW:
                self.hold[k] = now + BLOCK_S
                self._apply(k, LIMIT, now, "entropy")
            elif self.port_act[k] != ALLOW and now >= self.hold.get(k, 0) and now >= self.ent_flag_until:
                self._apply(k, ALLOW, now, "entropy")

    def _ppo_decide(self, per, g):
        h = np.concatenate([per, np.repeat(g[None], len(per), 0)], 1)
        for i, (W, b) in enumerate(self.policy):
            h = h @ W + b
            if i < 2:
                h = np.tanh(h)
        return h.argmax(1)

    def _apply(self, k, new, now, reason):
        dpid, port = k
        dp = self.datapaths[dpid]
        p, o = dp.ofproto_parser, dp.ofproto
        old = self.port_act[k]
        if new == old:
            return
        # remove previous restriction
        if old == LIMIT:
            dp.send_msg(p.OFPFlowMod(datapath=dp, command=o.OFPFC_DELETE_STRICT, priority=PRIO_LIMIT,
                                     match=p.OFPMatch(in_port=port), out_port=o.OFPP_ANY, out_group=o.OFPG_ANY))
            dp.send_msg(p.OFPMeterMod(dp, command=o.OFPMC_DELETE, meter_id=1000 + port))
        if old == BLOCK:
            dp.send_msg(p.OFPFlowMod(datapath=dp, command=o.OFPFC_DELETE_STRICT, priority=PRIO_BLOCK,
                                     match=p.OFPMatch(in_port=port), out_port=o.OFPP_ANY, out_group=o.OFPG_ANY))
            self.blocked.pop(k, None)
        if new == LIMIT:
            mid = 1000 + port
            dp.send_msg(p.OFPMeterMod(dp, command=o.OFPMC_ADD, flags=o.OFPMF_PKTPS, meter_id=mid,
                                      bands=[p.OFPMeterBandDrop(rate=LIMIT_PPS, burst_size=LIMIT_PPS)]))
            inst = [p.OFPInstructionMeter(mid), p.OFPInstructionActions(
                o.OFPIT_APPLY_ACTIONS, [p.OFPActionOutput(o.OFPP_CONTROLLER, o.OFPCML_NO_BUFFER)])]
            dp.send_msg(p.OFPFlowMod(datapath=dp, priority=PRIO_LIMIT, match=p.OFPMatch(in_port=port),
                                     instructions=inst))
        if new == BLOCK:
            dp.send_msg(p.OFPFlowMod(datapath=dp, priority=PRIO_BLOCK, match=p.OFPMatch(in_port=port),
                                     instructions=[]))
            self.blocked[k] = float("inf")
        self.fmod[dpid] += 1
        self.port_act[k] = new
        self.aw.writerow([round(now, 3), dpid, port, ["allow", "limit", "block"][new], reason])

    def _smart_step(self, now, backlog):
        ports = self._host_ports()
        if not ports:
            return
        per, g = self._port_features(ports, backlog)
        if os.environ.get("SDN_DEBUG_SPOOF") and int(now) % 10 == 0:
            self.logger.info("TRUNK %s n_host_ports=%d trunk=%s", now, len(ports), sorted(self.trunk))
        if DEFENSE == "rf":
            want = self._rf_decide(per, g)
            for i, k in enumerate(ports):
                cur = self.port_act[k]
                if want[i] > 0 and want[i] >= cur:
                    self.hold[k] = now + BLOCK_S
                if want[i] > cur or (want[i] < cur and now >= self.hold.get(k, 0)):
                    self._apply(k, int(want[i]), now, "rf")
        elif DEFENSE == "rule":
            want = self._rule_decide(per)
            for i, k in enumerate(ports):
                cur = self.port_act[k]
                if want[i] > cur or (want[i] < cur and now >= self.hold.get(k, 0)):
                    if want[i] > 0:
                        self.hold[k] = now + BLOCK_S
                    self._apply(k, int(want[i]), now, "rule")
        else:
            want = self._ppo_decide(per, g)
            for i, k in enumerate(ports):            # governor pardon (verified, time-limited)
                if self._gov_pardoned(k, now, per[i, 1]):
                    want[i] = 0
            if os.environ.get("SDN_DEBUG_SPOOF"):
                for i, k in enumerate(ports):
                    if want[i] != self.port_act[k]:
                        self.logger.info("PPODBG %s %s -> %d per=%s g=%s", now, k, want[i], np.round(per[i], 3).tolist(), np.round(g, 3).tolist())
            for i, k in enumerate(ports):
                # hysteresis (same hold as the rule defense): escalate at once, relax only after
                # PPO_HOLD_S seconds - stops allow/limit flapping that floods the switch with mods
                cur = self.port_act[k]
                if want[i] > 0 and want[i] >= cur:
                    self.hold[k] = now + PPO_HOLD_S          # still wanted: keep it held
                if want[i] > cur or (want[i] < cur and now >= self.hold.get(k, 0)):
                    self._apply(k, int(want[i]), now, "ppo")

    # ---------- statistics polling ----------
    def _stats_loop(self):
        while True:
            for dp in list(self.datapaths.values()):
                p = dp.ofproto_parser
                dp.send_msg(p.OFPFlowStatsRequest(dp))
                dp.send_msg(p.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY))
            hub.sleep(1)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats(self, ev):
        self.flow_count[ev.msg.datapath.id] = len(ev.msg.body)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats(self, ev):
        dpid = ev.msg.datapath.id
        self.port_rx[dpid] = sum(s.rx_packets for s in ev.msg.body if s.port_no < 0xffffff00 and s.rx_packets < (1 << 62))
        self.port_tx[dpid] = sum(s.tx_packets for s in ev.msg.body if s.port_no < 0xffffff00 and s.tx_packets < (1 << 62))
        for st in ev.msg.body:
            # OVS reports all-ones (2^64-1) for counters of a port being deleted (e.g. at teardown):
            # treat as unavailable so it never becomes a huge per-second rate
            if st.port_no < 0xffffff00 and st.rx_packets < (1 << 62):
                self.port_rx_now[(dpid, st.port_no)] = st.rx_packets
                self.port_cnt[(dpid, st.port_no)] = (st.rx_packets, st.rx_bytes, st.tx_packets, st.tx_bytes)

    # ---------- 1 Hz report ----------
    def _report_loop(self):
        while True:
            hub.sleep(1)
            now = time.time()
            if DEFENSE == "threshold":
                self._threshold_step(now)
            elif DEFENSE in ("rule", "ppo", "rf"):
                self._smart_step(now, self.events.qsize())
            elif DEFENSE == "entropy":
                self._entropy_step(now)
            elif DEFENSE == "llmport":
                self._llmport_step(now)
            ts = round(now, 3)
            backlog = self.events.qsize()
            self._gov_tick(now, backlog)
            for dpid in sorted(self.datapaths):
                pm = self.proc_ms[dpid]
                nblk = sum(1 for k in self.blocked if k[0] == dpid)
                self.w.writerow([ts, dpid, self.pin[dpid], self.fmod[dpid], backlog,
                                 self.flow_count[dpid],
                                 self.port_rx[dpid] - self.prev_rx[dpid],
                                 self.port_tx[dpid] - self.prev_tx[dpid],
                                 round(sum(pm) / len(pm), 3) if pm else 0, nblk])
                self.prev_rx[dpid], self.prev_tx[dpid] = self.port_rx[dpid], self.port_tx[dpid]
                self.pin[dpid] = self.fmod[dpid] = 0
                self.proc_ms[dpid] = []
            self.port_pin.clear()
            self.port_spoof.clear()
            self.port_dst.clear()
            self.port_rx_prev = dict(self.port_rx_now)
            self.out.flush()
            self.aout.flush()
