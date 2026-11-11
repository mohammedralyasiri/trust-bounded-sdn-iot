#!/usr/bin/env python3
"""
Telemetry poller for runs controlled by ONOS (cross-controller validation).

ONOS's REST API exposes devices, flow entries and port counters, but not a per-second
PacketIn count or the controller event-queue length; those columns are written as empty
(NaN) so summarize.py treats them as unavailable. All host-side service metrics
(MQTT delivery, new-session joins, new-flow setup, RTT) are measured exactly as with os-ken.

usage: onos_poll.py OUT_METRICS_CSV CTL_LOG [REST_BASE]
"""
import base64
import csv
import json
import sys
import time
import urllib.request

OUT, LOG = sys.argv[1], sys.argv[2]
BASE = sys.argv[3] if len(sys.argv) > 3 else "http://127.0.0.1:8181/onos/v1"
AUTH = "Basic " + base64.b64encode(b"onos:rocks").decode()


def get(path):
    req = urllib.request.Request(BASE + path, headers={"Authorization": AUTH})
    with urllib.request.urlopen(req, timeout=3) as r:
        return json.load(r)


def dpid(dev_id):                       # "of:0000000000000003" -> 3
    return int(dev_id.split(":")[1], 16)


seen = set()
prev_rx, prev_tx = {}, {}
with open(OUT, "w", newline="") as f, open(LOG, "a") as log:
    w = csv.writer(f)
    w.writerow(["ts", "dpid", "packet_in", "flow_mod", "backlog", "flow_count",
                "rx_pkts", "tx_pkts", "ctl_proc_ms", "blocked_ports"])
    log.write("controller=onos rest=%s\n" % BASE)
    log.flush()
    while True:
        t0 = time.time()
        try:
            devs = [d for d in get("/devices")["devices"] if d.get("available")]
            for d in devs:
                if d["id"] not in seen:
                    seen.add(d["id"])
                    log.write("switch connected dpid=%d\n" % dpid(d["id"]))
                    log.flush()
            nflows = {}
            for fl in get("/flows").get("flows", []):
                nflows[fl["deviceId"]] = nflows.get(fl["deviceId"], 0) + 1
            rx, tx = {}, {}
            for st in get("/statistics/ports").get("statistics", []):
                rx[st["device"]] = sum(p.get("packetsReceived", 0) for p in st.get("ports", []))
                tx[st["device"]] = sum(p.get("packetsSent", 0) for p in st.get("ports", []))
            ts = round(time.time(), 3)
            for d in devs:
                i = d["id"]
                w.writerow([ts, dpid(i), "", "", "", nflows.get(i, 0),
                            rx.get(i, 0) - prev_rx.get(i, rx.get(i, 0)),
                            tx.get(i, 0) - prev_tx.get(i, tx.get(i, 0)), "", 0])
            prev_rx, prev_tx = rx, tx
            f.flush()
            if int(ts) % 5 == 0:          # topology view of ONOS (diagnostics): links and learned hosts
                links = get("/links").get("links", [])
                hosts = get("/hosts").get("hosts", [])
                ips = sorted(ip for h in hosts for ip in h.get("ipAddresses", []))
                log.write("topo t=%.0f links=%d hosts=%d ips=%s\n" % (ts, len(links), len(hosts), ",".join(ips)))
                log.flush()
        except Exception as e:                                 # ONOS busy/overloaded: record a gap
            log.write("poll error: %s\n" % e)
            log.flush()
        time.sleep(max(0.0, 1.0 - (time.time() - t0)))
