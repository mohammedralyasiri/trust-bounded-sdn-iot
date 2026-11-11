"""V10 test (revflood): attack packets delivered to the targeted trusted devices, their MQTT latency,
time until the attacker ports were blocked, per run. Usage: python3 v10.py <results dir> [defense ...]"""
import sys, os, csv, glob, statistics as st
import pandas as pd
def mqtt_p95(run, names, t0, t1):
    lat = []
    for line in open(os.path.join(run, "mqtt_rx.log"), errors="ignore"):
        try:
            a, topic, p = line.strip().split("|")
            if topic.split("/")[-1] in names and t0 <= float(a) < t1:
                lat.append((float(a) - float(p.split()[1])) * 1000)
        except Exception:
            pass
    return (pd.Series(lat).quantile(.95) if lat else float("nan")), len(lat)
def one(run):
    ev = pd.read_csv(os.path.join(run, "events.csv")).iloc[0]
    a0 = ev.t_start + 40; a1 = ev.t_end
    pairs = [l.split() for l in open(os.path.join(run, "revflood_pairs.txt")) if l.strip()]
    att = {p[0] for p in pairs}; tgt = [p[3] for p in pairs]
    rx = 0.0
    for t in tgt:
        rows = [tuple(map(float, l.strip().split(","))) for l in open(os.path.join(run, "revflood_rx_%s.csv" % t)) if l.strip()]
        w = [n for ts, n in rows if a0 + 5 <= ts <= a1]
        if len(w) >= 2:
            rx += (w[-1] - w[0]) / max(1e-9, ([ts for ts, n in rows if a0 + 5 <= ts <= a1][-1] - [ts for ts, n in rows if a0 + 5 <= ts <= a1][0]))
    hosts = {h["host"]: (h["dpid"], h["port"]) for h in csv.DictReader(open(os.path.join(run, "hosts.csv")))}
    ap = {hosts[a] for a in att}
    blk = {}
    for x in csv.DictReader(open(os.path.join(run, "actions.csv"))):
        k = (x["dpid"], x["port"])
        if k in ap and x["action"] == "block" and float(x["ts"]) >= a0 and k not in blk:
            blk[k] = float(x["ts"]) - a0
    p95, n = mqtt_p95(run, set(tgt), a0, a1)
    s = pd.read_csv(os.path.join(run, "summary.csv")) if os.path.exists(os.path.join(run, "summary.csv")) else None
    att_row = s[s.phase == "attack"].iloc[0] if s is not None else {}
    return dict(attack_rx_pps=rx, attack_rx_per_target=rx / max(1, len(tgt)), targets=len(tgt),
                attackers_blocked=len(blk), block_s_median=st.median(blk.values()) if blk else float("nan"),
                target_mqtt_p95_ms=p95, target_mqtt_msgs=n,
                join_ok=att_row.get("join_ok_%", float("nan")), setup_fail=att_row.get("setup_fail_%", float("nan")),
                pin_s=att_row.get("packet_in_s", float("nan")))
if __name__ == "__main__":
    R = sys.argv[1]; defs = sys.argv[2:] or ["gov_rule", "gov_rule_v10"]
    rows = []
    for d in defs:
        for run in sorted(glob.glob(os.path.join(R, d, "rev*_seed*"))):
            if not os.path.exists(os.path.join(run, "events.meta")): continue
            r = one(run); r.update(defense=d, seed=int(run.split("seed")[-1])); rows.append(r)
    df = pd.DataFrame(rows); pd.set_option("display.width", 200)
    print(df.round(1).to_string(index=False)); print()
    print(df.groupby("defense").agg(["mean", "min", "max"]).round(1).T.to_string())
    df.to_csv(os.path.join(R, "v10_revflood.csv"), index=False)
