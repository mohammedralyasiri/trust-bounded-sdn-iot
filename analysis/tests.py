import pandas as pd, numpy as np, sys
from scipy import stats
df = pd.read_csv(sys.argv[1]); df = df[df.phase == 'attack']
def get(d, s, m): return df[(df.defense == d) & (df.scenario == s)][m].astype(float).values
C = [('flashcrowd','gov_hqwen3b','ppo4','join_ok_%'), ('flashcrowd','gov_rule','ppo4','join_ok_%'),
     ('flashcrowd','gov_hqwen3b','gov_rule','join_ok_%'), ('flashcrowd','gov_hqwen3b','gov_qwen3b','join_ok_%'),
     ('flashcrowd','ppo4c','ppo4','join_ok_%'),
     ('poison','gov_hqwen3b','ppo4','join_ok_%'), ('poison','gov_rule','ppo4','join_ok_%'),
     ('poison','gov_hqwen3b','gov_rule','join_ok_%'),
     ('inject','gov_hqwen3b_v7','gov_hqwen3b','join_ok_%'), ('inject','gov_hqwen3b_v7','gov_rule','join_ok_%'),
     ('inject','gov_hqwen3b','gov_rule','join_ok_%'), ('inject','gov_hqwen3b','ppo4','join_ok_%'),
     ('inject','gov_hqwen3b_v7','ppo4','join_ok_%'),
     ('inject','gov_hqwen3b_nb','gov_hqwen3b','join_ok_%'), ('poison','gov_rule_nb','gov_rule','join_ok_%'),
     ('mimicry','gov_hqwen3b','ppo4c','mqtt_lat_p95'), ('mimicry','gov_hqwen3b','ppo4','mqtt_lat_p95'),
     ('correlated','gov_hqwen3b','ppo4','join_ok_%'), ('botnet','ppo4','ppo','join_ok_%')]
rows = []
for s, a, b, m in C:
    x, y = get(a, s, m), get(b, s, m)
    u = stats.mannwhitneyu(x, y, alternative='two-sided')
    r = 2 * u.statistic / (len(x) * len(y)) - 1          # rank-biserial: +1 = a always larger
    rows.append([s, a, b, m, x.mean(), y.mean(), len(x), len(y), u.pvalue, r])
p = np.array([r[8] for r in rows]); o = np.argsort(p); k = len(p); adj = np.empty(k); run = 0
for i, j in enumerate(o):
    run = max(run, min(1, (k - i) * p[j])); adj[j] = run
for r, h in zip(rows, adj):
    print('%-10s %-15s vs %-13s %-12s %8.1f %8.1f n=%d/%d p=%.2g holm=%.2g r=%+.2f' % (*r[:4], r[4], r[5], r[6], r[7], r[8], h, r[9]))
