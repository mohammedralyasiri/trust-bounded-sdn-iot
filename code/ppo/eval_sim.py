"""Evaluate policies in the simulator: benign failure (attack window) and collateral, mean over seeds."""
import sys
import numpy as np
from sim_env import SDNIoTSim, SCENARIOS, NonePolicy, ThresholdPolicy, RulePolicy


def run(policy_factory, sc, seeds=10, n=96):
    f, bb, bl = [], [], []
    for s in range(seeds):
        e = SDNIoTSim(n, seed=1000 + s, scenario=sc)
        pol = policy_factory()
        per, g = e.reset()
        d = False
        while not d:
            (per, g), r, d, i = e.step(pol(per, g))
            if i["attacking"] or sc == "benign":
                f.append(i["fail"]); bb.append(i["blocked_benign"]); bl.append(i["limited_benign"])
    return np.mean(f) * 100, np.mean(bb) * 100, np.mean(bl) * 100


def table(policies, seeds=10):
    print("%-11s" % "scenario" + "".join("%26s" % k for k in policies))
    print("%-11s" % "" + "".join("%26s" % "fail% / blocked% / limited%" for _ in policies))
    for sc in SCENARIOS:
        row = "%-11s" % sc
        for k, fac in policies.items():
            row += "%26s" % ("%5.1f / %4.1f / %4.1f" % run(fac, sc, seeds))
        print(row)


if __name__ == "__main__":
    table({"none": NonePolicy, "threshold": ThresholdPolicy, "rule": RulePolicy})
