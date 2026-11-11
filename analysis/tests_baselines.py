"""Published-method baselines (rf = Mahar et al. 2026, entropy = Mousavi & St-Hilaire 2015) vs our rule governor
and PPO v4: Mann-Whitney U, rank-biserial r (+1 = first always larger), Holm over the whole family."""
import pandas as pd, numpy as np, sys
from scipy import stats
df = pd.read_csv(sys.argv[1]); df = df[df.phase == 'attack']
def get(d, s, m): return df[(df.defense == d) & (df.scenario == s)][m].astype(float).values
C = []
for b in ('rf', 'entropy'):
    for s in ('correlated', 'botnet', 'flashcrowd'):
        C.append((s, 'gov_rule', b, 'join_ok_%'))
    C += [('flashcrowd', 'gov_rule', b, 'setup_fail_%'), ('flashcrowd', 'gov_rule', b, 'mqtt_lat_p95')]
    for s in ('flood', 'burst', 'correlated', 'botnet'):
        C.append((s, 'gov_rule', b, 'setup_p95'))
rows = []
for s, a, b, m in C:
    x, y = get(a, s, m), get(b, s, m)
    u = stats.mannwhitneyu(x, y, alternative='two-sided')
    rows.append([s, a, b, m, x.mean(), y.mean(), len(x), len(y), u.pvalue, 2 * u.statistic / (len(x) * len(y)) - 1])
p = np.array([r[8] for r in rows]); o = np.argsort(p); k = len(p); adj = np.empty(k); run = 0
for i, j in enumerate(o):
    run = max(run, min(1, (k - i) * p[j])); adj[j] = run
for r, h in zip(rows, adj):
    print('%-10s %-8s vs %-8s %-13s %9.1f %9.1f n=%d/%d p=%.2g holm=%.2g r=%+.2f' % (*r[:4], r[4], r[5], r[6], r[7], r[8], h, r[9]))
