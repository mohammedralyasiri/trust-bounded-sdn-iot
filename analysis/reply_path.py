"""Table of the reply-path tests (Section 7.5): per arm, the attack offered to and delivered through the targets'
reply meters (switch meter counters), attackers blocked, the targets' MQTT p95 and join success.
Usage: python3 reply_path.py <results dir> [<results dir> ...] (arms: <defense>/<revflood|revown>_seed*)."""
import sys, os, glob, csv
import pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from meters import parse
import v10
def rate(S, sw, mid, a, b):
    ser = S.get((sw, mid), {}); ts = sorted(t for t in ser if a <= t <= b)
    if len(ts) < 2: return 0.0, 0.0
    (i0, d0), (i1, d1) = ser[ts[0]], ser[ts[-1]]; dt = ts[-1] - ts[0]
    return ((i1 - d1) - (i0 - d0)) / dt, (d1 - d0) / dt
rows = []
for R in sys.argv[1:]:
    S_all = pd.read_csv(os.path.join(R, 'summary_all.csv')); S_all = S_all[S_all.phase == 'attack']
    for run in sorted(glob.glob(os.path.join(R, '*', 'rev*_seed*'))):
        d = run.split('/')[-2]; sc, seed = os.path.basename(run).rsplit('_seed', 1); seed = int(seed)
        ev = pd.read_csv(os.path.join(run, 'events.csv')).iloc[0]; f0 = ev.t_start + 40
        hosts = {h['host']: (h['dpid'], int(h['port'])) for h in csv.DictReader(open(os.path.join(run, 'hosts.csv')))}
        tg = [l.split()[3] for l in open(os.path.join(run, 'revflood_pairs.txt')) if l.strip()]
        M = parse(os.path.join(run, 'meters.log'))
        p = dr = base = 0.0
        for t in tg:
            dp, port = hosts[t]
            a = rate(M, 's%s' % dp, 3000 + port, f0 + 5, ev.t_end); b = rate(M, 's%s' % dp, 3000 + port, ev.t_start + 2, f0 - 2)
            p += a[0]; dr += a[1]; base += b[0]
        o = v10.one(run)
        j = S_all[(S_all.defense == d) & (S_all.scenario == sc) & (S_all.seed == seed)]['join_ok_%']
        rows.append(dict(arm='%s/%s' % (sc, d), seed=seed, offered=p + dr, delivered=p, baseline=base, dropped=dr,
                         blocked=o['attackers_blocked'], block_s=o['block_s_median'], tgt_mqtt_ms=o['target_mqtt_p95_ms'],
                         join=float(j.iloc[0]) if len(j) else float('nan')))
df = pd.DataFrame(rows).sort_values(['arm', 'seed'])
pd.set_option('display.width', 200)
print(df.round(1).to_string(index=False)); print()
g = df.groupby('arm').agg(n=('seed', 'count'), off_lo=('offered', 'min'), off_hi=('offered', 'max'), del_lo=('delivered', 'min'),
    del_hi=('delivered', 'max'), base_lo=('baseline', 'min'), base_hi=('baseline', 'max'), blocked=('blocked', 'min'),
    blk_lo=('block_s', 'min'), blk_hi=('block_s', 'max'), mq_lo=('tgt_mqtt_ms', 'min'), mq_hi=('tgt_mqtt_ms', 'max'),
    join=('join', 'mean'), j_lo=('join', 'min'), j_hi=('join', 'max'))
print(g.round(1).T.to_string())
df.to_csv('reply_path_runs.csv', index=False)
