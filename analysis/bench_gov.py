"""Cost of the governance layer per round versus network size, measured on the real controller code
(governance.py) with stub datapaths that only count OpenFlow messages. Per size N: time of one state dump
(summary for the governor), one verification pass of 40 directives (budget = MAX_DIRECTIVES) and the per-second
tick, plus peak memory of the controller-side state. Messages per offload grant are counted too."""
import os, sys, time, json, tempfile, tracemalloc, random, collections
D = tempfile.mkdtemp(); os.environ.update(SDN_GOV="1", SDN_GOV_DIR=D, SDN_GOV_V10="1")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'code'))
import governance as G
class Msg:
    def __init__(self, *a, **k): pass
class Parser:
    def __getattr__(self, n): return Msg
class Ofp:
    def __getattr__(self, n): return 0
class DP:
    def __init__(self, i): self.id = i; self.ofproto_parser = Parser(); self.ofproto = Ofp(); self.sent = 0
    def send_msg(self, m): self.sent += 1
class Log:
    def info(self, *a): pass
class Ctl(G.GovernanceMixin):
    def __init__(self, E, H):
        self.logger = Log(); self.datapaths = {s: DP(s) for s in range(1, E + 2)}
        self.ports = [(e, h + 1) for e in range(1, E + 1) for h in range(1, H + 1)]
        self.port_ip = {k: "10.%d.%d.%d" % (k[0] // 250, k[0] % 250, k[1] - 1) for k in self.ports}
        self.port_pin = collections.Counter({k: random.randint(0, 20) for k in self.ports})
        self.port_spoof = collections.Counter(); self.port_dst = collections.defaultdict(set)
        self.port_act = {k: 0 for k in self.ports}; self.port_rx_now = {k: random.randint(0, 10**6) for k in self.ports}
        self.hold = {}; self.fmod = collections.Counter(); self._routes_cache = None; self.E = E
        self._gov_init()
    def _host_ports(self): return self.ports
    def _is_host_port(self, k): return True
    def _apply(self, *a): pass
    def _routes(self):   # one route per edge subnet on every switch, as in the testbed
        return {s: [(("10.%d.%d.0" % (e // 250, e % 250)), "255.255.255.0", 1) for e in range(1, self.E + 1)] for s in self.datapaths}
def run(N, H=12):
    E = N // H; random.seed(1); tracemalloc.start(); c = Ctl(E, H)
    acts = [dict(type="offload", ip=c.port_ip[k]) for k in random.sample(c.ports, 40)]
    t = time.perf_counter(); c._gov_dump(time.time(), 10); t_dump = time.perf_counter() - t
    with open(os.path.join(D, "gov_directives.json"), "w") as f: json.dump(dict(seq=1, actions=acts), f)
    before = sum(d.sent for d in c.datapaths.values())
    t = time.perf_counter(); c._gov_read(time.time()); t_read = time.perf_counter() - t
    sent = sum(d.sent for d in c.datapaths.values()) - before
    # a second round, with the table-1 routes already in place: the steady-state cost of 40 new grants
    acts2 = [dict(type="offload", ip=c.port_ip[k]) for k in random.sample([k for k in c.ports if k not in c.offloaded], 40)]
    for k in list(c.offloaded): c._gov_revoke(k)
    with open(os.path.join(D, "gov_directives.json"), "w") as f: json.dump(dict(seq=2, actions=acts2), f)
    before2 = sum(d.sent for d in c.datapaths.values())
    t = time.perf_counter(); c._gov_read(time.time()); t_read2 = time.perf_counter() - t
    sent2 = (sum(d.sent for d in c.datapaths.values()) - before2) / max(1, len(c.offloaded))
    t = time.perf_counter(); c._gov_tick(time.time(), 0); t_tick = time.perf_counter() - t
    peak = tracemalloc.get_traced_memory()[1]; tracemalloc.stop()
    return E, t_dump, t_read, t_tick, sent / max(1, len(c.offloaded)), peak, len(c.offloaded), t_read2, sent2
print("devices,edge_switches,dump_ms,first_round40_ms,steady_round40_ms,tick_ms,ofmsgs_per_grant_first,ofmsgs_per_grant_steady,state_peak_MB,granted")
for N in (96, 384, 1000, 2500, 5000, 10000):
    r = [run(N) for _ in range(3)]; best = lambda i: min(x[i] for x in r)
    print("%d,%d,%.1f,%.1f,%.1f,%.2f,%.1f,%.1f,%.1f,%d" % (N, r[0][0], best(1)*1e3, best(2)*1e3, best(7)*1e3, best(3)*1e3, r[0][4], r[0][8], r[0][5]/1e6, r[0][6]))
