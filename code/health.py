#!/usr/bin/env python3
"""Testbed health check of one finished run (exit 0 = healthy, 1 = redo).
Healthy means the HOST was not the bottleneck before any attack or defense action:
pre-attack MQTT p95 <= 8 ms (normal ~4.5 ms) and no telemetry gap > 5 s before the attack ends
(a gap that starts during the attack can be the controller itself failing, which is a real outcome)."""
import sys, os
import pandas as pd
run = sys.argv[1]
why = []
try:
    ev = pd.read_csv(os.path.join(run, "events.csv")).iloc[0]
    lat = []
    for line in open(os.path.join(run, "mqtt_rx.log")):
        try:
            a, _, p = line.strip().split("|")
            if ev.t_measure + 5 <= float(a) < ev.t_start:
                lat.append((float(a) - float(p.split()[1])) * 1000)
        except Exception:
            pass
    if not lat:
        why.append("no pre-attack MQTT samples")
    elif pd.Series(lat).quantile(.95) > float(os.environ.get("SDN_HEALTH_MQTT_MS", "8")):
        why.append("slow host before the attack (MQTT p95 %.1f ms)" % pd.Series(lat).quantile(.95))
    ts = pd.read_csv(os.path.join(run, "metrics_ctl.csv")).ts.drop_duplicates().sort_values()
    pre = ts[(ts >= ev.t_measure) & (ts <= ev.t_start)]
    if len(pre) < 2 or pre.diff().max() > 5:
        why.append("telemetry gap before the attack (host paused)")
except Exception as e:
    why.append("unreadable: %s" % e)
if why:
    print("   HEALTH: redo ->", "; ".join(why))
    sys.exit(1)
