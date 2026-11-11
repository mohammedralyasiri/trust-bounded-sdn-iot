"""
Calibrated fluid simulator of an SDN-IoT control plane, used to train the PPO defense.

One step = 1 s (the controller's telemetry period). N host-facing switch ports, one device each.
Per port the controller sees (exactly what telemetry_switch.py can compute):
    pin      PacketIn messages from the port in the last second (table misses)
    spoof    share of those PacketIns whose IPv4 source is not the device's own address
    ndst     distinct IPv4 destinations among them
    dp       data-plane packets received on the port (port counters; visible even when blocked)
    act      current action on the port (allow / limit / block), one-hot
Global context: controller backlog / 128, total PacketIn / service rate, flow-table fill.

Actions per port: 0 allow, 1 limit (switch meter: new-flow requests from the port capped at
LIMIT_PPS), 2 block (drop everything from the port).

Controller model (calibrated on the testbed: queue capacity 128 events, service rate measured
~870-1000 msg/s on the VM): Q' = clip(Q + arrivals - mu, 0, 128); arrivals beyond the free
queue space are dropped. A benign new flow (from a non-compromised device) fails if its request is dropped or waits > 2 s.

Reward (shared by all ports): -(benign new-flow failure rate) - 1.0 * (share of benign devices
blocked) - 0.2 * (share of benign devices limited) - 0.05 * (share of ports whose action changed).
"""
import os
import numpy as np

ALLOW, LIMIT, BLOCK = 0, 1, 2
QCAP = 128
LIMIT_PPS = 10.0
LIMIT_PEN = float(os.environ.get("SIM_LIMIT_PEN", "0.2"))   # cost of rate-limiting a benign device
# v4 calibration on the 96-device testbed (phase-3 data): saturated controller throughput 390-820 PacketIn/s,
# and every new flow toward the broker misses on the edge AND the core switch (~2 PacketIns per flow).
V4 = os.environ.get("SIM_V4", "1") == "1"
MU_LO, MU_HI = (350.0, 800.0) if V4 else (500.0, 800.0)
BLOCK_PEN = float(os.environ.get("SIM_BLOCK_PEN", "1.0"))    # cost of blocking a benign device
ATT_LIMIT_CREDIT = float(os.environ.get("SIM_ATT_LIMIT_CREDIT", "0.2" if V4 else "0.5"))
F_PORT = 7          # per-port feature size
F_GLOB = 3

SCENARIOS = ["benign", "flood", "lowslow", "burst", "mimicry", "correlated", "botnet", "scanbot",
             "adaptive", "flashcrowd"]
# flashcrowd: NO attacker - 30% of devices legitimately open many new flows to many destinations at
# once (e.g. firmware/CDN fetch). Looks like scanbot to a static rule; blocking them is collateral.


class SDNIoTSim:
    def __init__(self, n_ports=96, seed=0, scenario=None, horizon=120):
        self.rng = np.random.default_rng(seed)
        self.n_fixed = n_ports
        self.fixed_scenario = scenario
        self.H = horizon

    # ---------------- episode setup ----------------
    def reset(self):
        r = self.rng
        self.N = self.n_fixed if self.n_fixed else int(r.integers(24, 129))
        self.sc = self.fixed_scenario or r.choice(SCENARIOS)
        self.mu = r.uniform(MU_LO, MU_HI)                    # effective controller service rate (msg/s)
        self.hops = r.uniform(1.7, 2.1)                      # PacketIns per new flow (edge + core switch)
        self.t = 0
        self.a0, self.a1 = int(r.integers(10, 40)), None
        self.a1 = self.a0 + int(r.integers(40, 70))
        self.Q = 0.0
        self.act = np.zeros(self.N, int)
        self.benign_newflow = r.uniform(0.05, 0.6, self.N)   # new-flow requests/s per device
        self.dp_base = r.uniform(0.3, 2.0, self.N)           # data-plane pkt/s per device
        self.att = np.zeros(self.N, bool)
        sc, N = self.sc, self.N
        if sc in ("flood", "lowslow", "burst", "adaptive"):
            self.att[r.choice(N, 1, replace=False)] = True
        elif sc == "correlated":
            self.att[r.choice(N, max(2, N // 12), replace=False)] = True
        elif sc in ("botnet", "scanbot"):
            self.att[r.choice(N, max(2, int(0.3 * N)), replace=False)] = True
        self.crowd = np.zeros(N, bool)
        if sc == "flashcrowd":
            self.crowd[r.choice(N, max(2, int(0.3 * N)), replace=False)] = True
        self.crowd_rate = r.uniform(30, 90)
        self.flood_rate = r.uniform(500, 1500)
        self.bot_rate = r.uniform(25, 49)                    # stays under a 50 msg/s threshold
        return self._obs(np.zeros(self.N), np.zeros(self.N), np.zeros(self.N), self._dp(False))

    def _attacking(self):
        if not (self.a0 <= self.t < self.a1):
            return False
        if self.sc == "burst":
            return ((self.t - self.a0) // 5) % 2 == 0
        return True

    def _dp(self, on):
        dp = self.rng.poisson(self.dp_base).astype(float)
        if on and self.sc == "mimicry":
            dp += self.rng.poisson(50.0, self.N)            # synchronized benign-looking wave
        return dp

    # ---------------- one second ----------------
    def step(self, action):
        r = self.rng
        action = np.asarray(action, int)
        changed = (action != self.act).mean()
        self.act = action
        on = self._attacking()

        ben = r.poisson(self.benign_newflow).astype(float)   # benign new-flow requests
        att = np.zeros(self.N)
        spoof_n = np.zeros(self.N)
        ndst = np.minimum(ben, 3.0)
        if on and self.sc == "flashcrowd":
            k = self.crowd.sum()
            ben[self.crowd] += self.crowd_rate * r.uniform(0.9, 1.1, k)
            ndst[self.crowd] += np.minimum(ben[self.crowd], 40)
        if on and self.sc not in ("mimicry", "benign", "flashcrowd"):
            rate = {"flood": self.flood_rate, "correlated": self.flood_rate, "burst": self.flood_rate,
                    "lowslow": 20.0, "botnet": self.bot_rate, "scanbot": self.bot_rate,
                    "adaptive": self.flood_rate}[self.sc]
            if self.sc == "adaptive" and (self.act[self.att] != ALLOW).any():
                rate = 40.0                                   # attacker backs off when throttled
            att[self.att] = rate * r.uniform(0.95, 1.05, self.att.sum())   # tools send at fixed rate
            if self.sc == "scanbot":                          # own IP, many destinations
                ndst[self.att] += np.minimum(att[self.att], 60)
            else:                                             # spoofed random sources
                spoof_n[self.att] = att[self.att]
                ndst[self.att] += 1
        demand = ben + att
        dp = self._dp(on) + demand

        # actions: what reaches the controller
        passed = demand.copy()
        lim = self.act == LIMIT
        passed[lim] = np.minimum(demand[lim], r.poisson(LIMIT_PPS, lim.sum()))
        passed[self.act == BLOCK] = 0.0
        seen_pin = passed
        tot = passed.sum() * (self.hops if V4 else 1.0)
        free = QCAP - self.Q
        served = min(self.mu, self.Q + tot)
        drop_frac = max(0.0, (tot - (free + self.mu))) / tot if tot > 0 else 0.0
        self.Q = float(np.clip(self.Q + tot - served, 0, QCAP))
        wait = self.Q / self.mu
        late = 1.0 if wait > 2.0 else 0.0

        # benign outcome
        ben_ok_share = np.where(demand > 0, passed / np.maximum(demand, 1e-9), 1.0)
        ben_ok_share[self.act == BLOCK] = 0.0
        ok = ben_ok_share * (1 - drop_frac) * (1 - late)      # success share of each device's requests
        benign = ~self.att                                    # compromised devices are excluded
        active = benign & (ben > 0)
        # per-device average (fairness): every benign device that tried to open a flow counts equally
        fail = float(1 - ok[active].mean()) if active.any() else 0.0
        blocked_b = ((self.act == BLOCK) & benign).sum() / max(1, benign.sum())
        limited_b = ((self.act == LIMIT) & benign).sum() / max(1, benign.sum())
        reward = -fail - BLOCK_PEN * blocked_b - LIMIT_PEN * limited_b - 0.05 * changed

        self.t += 1
        done = self.t >= self.H
        spoof = np.where(seen_pin > 0, np.minimum(spoof_n, seen_pin) / np.maximum(seen_pin, 1e-9), 0.0)
        # the controller only sees destinations of requests that reach it (a limited port shows <= LIMIT_PPS)
        ndst_seen = np.minimum(ndst, np.round(seen_pin)) if V4 else np.where(seen_pin > 0, ndst, 0.0)
        obs = self._obs(seen_pin, spoof, ndst_seen, dp)
        # per-port credit (training only; uses ground truth, never seen by the policy):
        # restricting a benign device is penalised on THAT port; restricting a sending attacker is rewarded
        local = np.zeros(self.N)
        local[benign & (self.act == LIMIT)] -= LIMIT_PEN
        local[benign & (self.act == BLOCK)] -= BLOCK_PEN
        if on:
            local[self.att & (self.act == BLOCK)] += 0.5
            local[self.att & (self.act == LIMIT)] += ATT_LIMIT_CREDIT
            local[self.att & (self.act == ALLOW)] -= 0.5
        info = dict(local=local, fail=fail, blocked_benign=blocked_b, limited_benign=limited_b,
                    blocked_att=((self.act == BLOCK) & self.att).sum() / max(1, self.att.sum()),
                    queue=self.Q, attacking=on)
        return obs, reward, done, info

    def _obs(self, pin, spoof, ndst, dp):
        per = np.stack([np.log1p(pin) / 7, spoof, np.log1p(ndst) / 4, np.log1p(dp) / 7,
                        self.act == ALLOW, self.act == LIMIT, self.act == BLOCK], 1).astype(np.float32)
        g = np.array([self.Q / QCAP, pin.sum() / (600.0 if V4 else self.mu), 0.0], np.float32)   # controller: host-port PacketIn / MU_EST
        return per, g


# ---------------- reference policies (same logic as the controller baselines) ----------------
class NonePolicy:
    def __call__(self, per, g):
        return np.zeros(len(per), int)


class TimedPolicy:
    """Base: an action, once taken on a port, is held for HOLD seconds (rule hard-timeout)."""
    HOLD = 10

    def __init__(self):
        self.until = None
        self.held = None

    def decide(self, per, g):
        raise NotImplementedError

    def __call__(self, per, g):
        n = len(per)
        if self.until is None or len(self.until) != n:
            self.until, self.held = np.zeros(n), np.zeros(n, int)
        self.until -= 1
        new = self.decide(per, g)
        upd = (new > self.held) | (self.until <= 0)
        self.held[upd] = new[upd]
        self.until[upd & (new > 0)] = self.HOLD
        return self.held.copy()


class ThresholdPolicy(TimedPolicy):
    """Static per-port PacketIn threshold -> block (the 'threshold' controller defense)."""
    def decide(self, per, g, th=50):
        pin = np.expm1(per[:, 0] * 7)
        return np.where(pin > th, BLOCK, ALLOW)


class RulePolicy(TimedPolicy):
    """Strong hand-written heuristic ('rule' controller defense): block spoofing or scanning
    ports, limit heavy ports."""
    def decide(self, per, g):
        pin = np.expm1(per[:, 0] * 7)
        ndst = np.expm1(per[:, 2] * 4)
        a = np.zeros(len(per), int)
        a[pin > 20] = LIMIT
        a[(per[:, 1] > 0.5) & (pin > 5)] = BLOCK
        a[ndst > 10] = BLOCK
        return a


class HeldPolicy:
    """Wraps a learned policy with the controller's hysteresis: escalate at once, relax only after
    HOLD seconds without the restriction being wanted (SDN_PPO_HOLD_S in telemetry_switch.py)."""
    def __init__(self, inner, hold=10):
        self.inner, self.hold, self.cur, self.until = inner, hold, None, None

    def __call__(self, per, g):
        want = self.inner(per, g)
        n = len(want)
        if self.cur is None or len(self.cur) != n:
            self.cur, self.until = np.zeros(n, int), np.zeros(n)
        self.until -= 1
        keep = (want > 0) & (want >= self.cur)
        self.until[keep] = self.hold
        ch = (want > self.cur) | ((want < self.cur) & (self.until <= 0))
        self.cur[ch] = want[ch]
        return self.cur.copy()
