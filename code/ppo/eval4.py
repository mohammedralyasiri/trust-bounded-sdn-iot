"""Sim evaluation at the 96-device testbed scale with v4 calibration: fail% / blocked-benign% / limited-benign%."""
import sys
import numpy as np
from sim_env import NonePolicy, ThresholdPolicy, RulePolicy
from eval_sim import table
from ppo_np import PPOPolicy as load_policy

pols = {"none": NonePolicy, "threshold": ThresholdPolicy, "rule": RulePolicy}
for p in sys.argv[1:]:
    pols[p.split("/")[-1].replace(".npz", "")] = (lambda f=p: load_policy(f))
table(pols, seeds=10)
