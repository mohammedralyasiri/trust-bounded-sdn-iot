#!/usr/bin/env python3
"""
Telemetry poller for runs controlled by POX (cross-controller comparison).
POX exposes no counters, so the flow-table size per switch is read from OVS itself
(ovs-ofctl dump-aggregate, OpenFlow 1.0) once per second. PacketIn rate, event backlog and
controller processing time are not observable and are written as empty (NaN), as for ONOS.
usage: pox_poll.py OUT_METRICS_CSV N_SWITCHES
"""
import csv
import re
import subprocess
import sys
import time

OUT, N = sys.argv[1], int(sys.argv[2])
with open(OUT, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["ts", "dpid", "packet_in", "flow_mod", "backlog", "flow_count",
                "rx_pkts", "tx_pkts", "ctl_proc_ms", "blocked_ports"])
    while True:
        t0 = time.time()
        ts = round(t0, 3)
        for i in range(1, N + 1):
            try:
                o = subprocess.run(["ovs-ofctl", "-O", "OpenFlow10", "dump-aggregate", "s%d" % i],
                                   capture_output=True, text=True, timeout=2).stdout
                m = re.search(r"flow_count=(\d+)", o)
                if m:
                    w.writerow([ts, i, "", "", "", int(m.group(1)), "", "", "", 0])
            except Exception:
                pass
        f.flush()
        time.sleep(max(0.0, 1.0 - (time.time() - t0)))
