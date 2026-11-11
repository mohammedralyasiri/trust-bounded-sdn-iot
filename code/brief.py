#!/usr/bin/env python3
"""One line per finished run with the key attack-phase metrics (printed by campaign.sh)."""
import sys
import summarize
r = summarize.summarize(sys.argv[1])
a = r.loc["attack"]
g = lambda c: a[c] if c in a.index else float("nan")
print("   attack: join_ok=%.0f%%  setup_fail=%.0f%%  mqtt_p95=%.1fms  collateral=%.0f  pin=%.0f/s  ctl_gap=%.1fs"
      % (g("join_ok_%"), g("setup_fail_%"), g("mqtt_lat_p95"), g("collateral"), g("packet_in_s"), g("ctl_gap_max_s")))
