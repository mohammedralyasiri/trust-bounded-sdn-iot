#!/usr/bin/env python3
"""
Supervised hybrid tree-ensemble baseline after Mahar et al. (2026, Scientific Reports): a Random Forest and
a gradient-boosted tree model (scikit-learn GradientBoosting in place of XGBoost) combined by soft voting,
on the per-port statistics the controller collects.
Trained on the same calibrated simulator as the PPO policy, all scenarios incl. the benign flash crowd,
with no defense acting (all ports allowed). Label = port belongs to an attacker AND the attack is on.
Features: log PacketIn rate, foreign-source share, log distinct destinations, log data packets,
controller backlog, total PacketIn / service rate.
Exports the forest as flat numpy arrays (rf_model.npz) so the controller needs no scikit-learn.
"""
import sys
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1 else "ppo")
from sim_env import SDNIoTSim, SCENARIOS

X, y = [], []
rng = np.random.default_rng(7)
for ep in range(600):
    sc = SCENARIOS[ep % len(SCENARIOS)]
    env = SDNIoTSim(n_ports=96, seed=int(rng.integers(1 << 30)), scenario=sc, horizon=120)
    per, g = env.reset()
    for t in range(120):
        lab = env.att & env._attacking()
        (per, g), _, done, _ = env.step(np.zeros(env.N, int))
        f = np.concatenate([per[:, :4], np.repeat(g[None, :2], len(per), 0)], 1)
        X.append(f); y.append(lab.astype(int))
        if done:
            break
X, y = np.concatenate(X), np.concatenate(y)
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=1, stratify=y)
rf = RandomForestClassifier(n_estimators=50, max_depth=10, class_weight="balanced", n_jobs=-1, random_state=1)
rf.fit(Xtr, ytr)
sub = np.random.default_rng(2).choice(len(Xtr), 400000, replace=False)
gb = GradientBoostingClassifier(n_estimators=100, max_depth=3, learning_rate=0.1, random_state=1)
gb.fit(Xtr[sub], ytr[sub])
p_h = (rf.predict_proba(Xte)[:, 1] + gb.predict_proba(Xte)[:, 1]) / 2
print("RF\n", classification_report(yte, rf.predict(Xte), digits=4))
print("hybrid RF+GB\n", classification_report(yte, (p_h > 0.5).astype(int), digits=4))
trees = rf.estimators_
L = max(t.tree_.node_count for t in trees)
def pad(a, fill):
    return np.array([np.pad(x, (0, L - len(x)), constant_values=fill) for x in a])
feat = pad([t.tree_.feature for t in trees], -2)
thr = pad([t.tree_.threshold for t in trees], 0.0)
left = pad([t.tree_.children_left for t in trees], -1)
right = pad([t.tree_.children_right for t in trees], -1)
val = pad([t.tree_.value[:, 0, 1] / t.tree_.value[:, 0, :].sum(1) for t in trees], 0.0)
gt = [e[0] for e in gb.estimators_]
G = max(t.tree_.node_count for t in gt)
def padg(a, fill):
    return np.array([np.pad(x, (0, G - len(x)), constant_values=fill) for x in a])
init = float(gb._raw_predict_init(Xte[:1])[0, 0])
np.savez("rf_model.npz", feature=feat, threshold=thr, left=left, right=right, p1=val,
         gb_feature=padg([t.tree_.feature for t in gt], -2), gb_threshold=padg([t.tree_.threshold for t in gt], 0.0),
         gb_left=padg([t.tree_.children_left for t in gt], -1), gb_right=padg([t.tree_.children_right for t in gt], -1),
         gb_value=padg([t.tree_.value[:, 0, 0] for t in gt], 0.0), gb_init=np.array(init), gb_lr=np.array(gb.learning_rate))
np.savez("rf_check.npz", X=Xte[:5000], p=p_h[:5000])
print("trees", len(trees), "max nodes", L, "samples", len(y), "positives", int(y.sum()))
