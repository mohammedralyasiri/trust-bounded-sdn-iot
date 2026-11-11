"""Sensitivity (power) analysis for the two-sided Mann-Whitney U test used in the paper.
For each sample size: the smallest attainable p, and the smallest rank-biserial effect |r| (normal shift model)
detectable with 80% power at alpha = .05 and at a Holm-adjusted alpha of .05/6. Monte Carlo, 4,000 draws per point."""
import numpy as np
from scipy import stats
from math import comb
rng = np.random.default_rng(1)
def power(n1, n2, d, alpha, R=4000):
    hit = 0
    for _ in range(R):
        x = rng.normal(0, 1, n1); y = rng.normal(d, 1, n2)
        if stats.mannwhitneyu(x, y, alternative='two-sided', method='exact').pvalue < alpha: hit += 1
    return hit / R
def mde(n1, n2, alpha):
    lo, hi = 0.0, 6.0
    if power(n1, n2, hi, alpha, 800) < 0.8: return None
    for _ in range(14):
        mid = (lo + hi) / 2
        (hi, lo) = (mid, lo) if power(n1, n2, mid, alpha, 1500) >= 0.8 else (hi, mid)
    d = hi; A = stats.norm.cdf(d / np.sqrt(2)); return d, 2 * A - 1
for n1, n2 in [(10, 10), (10, 5), (5, 5), (5, 3), (3, 3)]:
    pmin = 2 / comb(n1 + n2, n1)
    r1 = mde(n1, n2, 0.05); r2 = mde(n1, n2, 0.05 / 6)
    f = lambda r: 'not reachable' if r is None else 'd=%.2f, |r|=%.2f' % r
    print('n=%2d vs %2d  min p=%.2g   80%% power at .05: %s   at .05/6: %s' % (n1, n2, pmin, f(r1), f(r2)))
