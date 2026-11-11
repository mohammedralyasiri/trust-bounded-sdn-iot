"""revflood: traffic offered to and delivered through the reply meters (3000 + port) of the six targeted trusted
devices, from the switches' own meter counters (the targets' kernels drop random-source packets, so the sinks undercount).
Window: 45 s after the flood starts to the end of the surge; baseline: the 40 s before the flood (crowd already offloaded)."""
import sys, os, glob, csv
import pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from meters import parse
def rates(S, sw, mid, t0, t1):
    ser = S.get((sw, mid), {}); ts = sorted(t for t in ser if t0 <= t <= t1)
    if len(ts) < 2: return float('nan'), float('nan')
    (i0, d0), (i1, d1) = ser[ts[0]], ser[ts[-1]]; dt = ts[-1] - ts[0]
    return ((i1 - d1) - (i0 - d0)) / dt, (d1 - d0) / dt   # passed, dropped (pkt/s)
rows = []
for run in sorted(glob.glob(os.path.join(sys.argv[1], '*', 'rev*_seed*'))):
    d = os.path.basename(os.path.dirname(run)); seed = int(run.split('seed')[-1])
    ev = pd.read_csv(os.path.join(run, 'events.csv')).iloc[0]; f0 = ev.t_start + 40
    hosts = {h['host']: (h['dpid'], int(h['port'])) for h in csv.DictReader(open(os.path.join(run, 'hosts.csv')))}
    tg = [l.split()[3] for l in open(os.path.join(run, 'revflood_pairs.txt')) if l.strip()]
    S = parse(os.path.join(run, 'meters.log'))
    sw = lambda dp: 's%s' % dp
    p_att = d_att = p_base = 0.0
    for t in tg:
        dp, port = hosts[t]
        a = rates(S, sw(dp), 3000 + port, f0 + 5, ev.t_end); b = rates(S, sw(dp), 3000 + port, ev.t_start + 2, f0 - 2)
        p_att += a[0]; d_att += a[1]; p_base += b[0]
    rows.append(dict(defense=d, seed=seed, delivered_pps=p_att, dropped_at_target_meter_pps=d_att, baseline_pps=p_base,
                     attack_delivered_pps=p_att - p_base, offered_pps=p_att + d_att))
df = pd.DataFrame(rows); print(df.round(1).to_string(index=False)); print()
print(df.groupby('defense')[['delivered_pps', 'dropped_at_target_meter_pps', 'baseline_pps', 'offered_pps']].agg(['mean', 'min', 'max']).round(0).T.to_string())
df.to_csv(os.path.join(sys.argv[1], 'v10_meters.csv'), index=False)
