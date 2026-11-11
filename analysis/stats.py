import pandas as pd, numpy as np, sys
from scipy import stats
df = pd.read_csv(sys.argv[1]); df = df[df.phase == 'attack'].copy()
# exclude runs with a degraded host before the attack (documented)
excl = {('onos','mimicry',1),('onos','correlated',1),('onos','botnet',1),('onos','flashcrowd',1),
        ('nonec','mimicry',1),('nonec','botnet',1),('nonec','correlated',1)}
df = df[[ (d,s,int(k)) not in excl for d,s,k in zip(df.defense, df.scenario, df.seed)]]
def ci(x):
    x = np.asarray(x, float); x = x[~np.isnan(x)]; n = len(x)
    if n < 2: return (x.mean() if n else np.nan, np.nan, n)
    return x.mean(), stats.t.ppf(.975, n-1) * x.std(ddof=1) / np.sqrt(n), n
def rbc(a, b):
    u = stats.mannwhitneyu(a, b, alternative='two-sided')
    return u.pvalue, 1 - 2 * u.statistic / (len(a) * len(b))   # rank-biserial (positive: a > b)... sign check below
defs = sys.argv[2].split(','); scen = sys.argv[3].split(','); metrics = sys.argv[4].split(',')
for m in metrics:
    print('\n##', m)
    print('scenario | ' + ' | '.join(defs))
    for s in scen:
        row = []
        for d in defs:
            x = df[(df.defense == d) & (df.scenario == s)][m]
            mu, h, n = ci(x)
            row.append('–' if n == 0 else ('%.1f ± %.1f (n=%d)' % (mu, h, n) if n > 1 else '%.1f (n=1)' % mu))
        print(s + ' | ' + ' | '.join(row))
