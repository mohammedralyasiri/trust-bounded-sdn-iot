"""Scaling study: per run, network size, controller CPU (% of one core) and memory during the attack, rule counts,
service metrics. Usage: python3 scale.py <results dir> (reads summary_all.csv there and ctl_res.csv per run)."""
import sys, os, glob, re
import pandas as pd
R = sys.argv[1]
S = pd.read_csv(os.path.join(R, "summary_all.csv")); A = S[S.phase == "attack"]
rows = []
for run in sorted(glob.glob(os.path.join(R, "*", "*_seed*"))):
    d = os.path.basename(os.path.dirname(run)); sc, seed = os.path.basename(run).rsplit("_seed", 1)
    m = re.search(r"_e(\d+)$", d); E = int(m.group(1)) if m else 8
    if not (m or d in ("ppo4", "gov_rule", "gov_rule_v10")) or sc not in ("flashcrowd", "botnet"): continue
    f = os.path.join(run, "ctl_res.csv")
    if not os.path.exists(f) or not os.path.exists(os.path.join(run, "events.csv")): continue
    ev = pd.read_csv(os.path.join(run, "events.csv")).iloc[0]
    c = pd.read_csv(f).dropna()
    c = c[(c.ts >= ev.t_start) & (c.ts <= ev.t_end)]
    if len(c) < 3: continue
    cpu = (c.cpu_jiffies.diff() / c.hz.iloc[0] / c.ts.diff() * 100).dropna()
    a = A[(A.defense == d) & (A.scenario == sc) & (A.seed == int(seed))]
    if a.empty: continue
    a = a.iloc[0]
    rows.append(dict(defense=re.sub(r"_e\d+$", "", d), devices=int(ev.n_devices), scenario=sc, seed=int(seed),
                     cpu_mean=cpu.mean(), cpu_p95=cpu.quantile(.95), rss_mb=c.rss_kb.max() / 1024,
                     join_ok=a["join_ok_%"], setup_fail=a["setup_fail_%"], mqtt_p95=a["mqtt_lat_p95"],
                     pin_s=a["packet_in_s"], flows_max=a["flows_max"], collateral=a["collateral"]))
df = pd.DataFrame(rows)
pd.set_option("display.width", 220)
g = df.groupby(["scenario", "defense", "devices"]).agg(n=("seed", "count"), join_ok=("join_ok", "mean"), setup_fail=("setup_fail", "mean"),
    mqtt_p95=("mqtt_p95", "mean"), pin_s=("pin_s", "mean"), flows_max=("flows_max", "mean"), cpu_mean=("cpu_mean", "mean"),
    cpu_p95=("cpu_p95", "mean"), rss_mb=("rss_mb", "max"), collateral=("collateral", "mean"))
print(g.round(1).to_string())
df.to_csv(os.path.join(R, "scale_runs.csv"), index=False)
