#!/usr/bin/env python3
"""
Summarize one run per phase (before / attack / after), or compare all runs.

  python summarize.py results/none/flood_seed1
  python summarize.py --compare results        -> results/summary_all.csv (+ printed table)

Metrics
  control plane : packet_in_s, flow_mod_s, backlog_max, flows_max
  established   : rtt_p95 (probe), mqtt_lat_p50/p95 (ms), mqtt_loss_% (sequence gaps)
  new sessions  : setup_fail_% / setup_p95 (ping to a device whose flow expired),
                  join_ok_% / join_p95 (fresh MQTT session to the broker)
  defense       : blocks, collateral (benign ports blocked)
"""
import glob
import os
import sys

import numpy as np
import pandas as pd

PH = ["before", "attack", "after"]


def phase_of(ts, ev):
    return pd.cut(ts, [-1e18, ev.t_start, ev.t_end, 1e18], labels=PH)


def summarize(run):
    ev = pd.read_csv(os.path.join(run, "events.csv")).iloc[0]
    keep = lambda d: d[d.ts >= ev.t_measure + 5].copy()
    out = pd.DataFrame(index=pd.Index(PH, name="phase"))

    ctl = keep(pd.read_csv(os.path.join(run, "metrics_ctl.csv")))
    ctl["phase"] = phase_of(ctl.ts, ev)
    agg = ctl.groupby(["ts", "phase"], observed=True).agg(
        packet_in=("packet_in", "sum"), flow_mod=("flow_mod", "sum"),
        backlog=("backlog", "max"), flow_count=("flow_count", "sum")).reset_index()
    # counters are per report interval (nominally 1 s); a stalled controller loop stretches the
    # interval, so rates are counts / interval, and the longest stall is reported (ctl_gap_max_s)
    agg = agg.sort_values("ts")
    agg["dt"] = agg.ts.diff().fillna(1.0).clip(lower=0.5)
    g = agg.groupby("phase", observed=True)
    out["packet_in_s"] = g.packet_in.sum() / g.dt.sum()
    out["flow_mod_s"] = g.flow_mod.sum() / g.dt.sum()
    out["ctl_gap_max_s"] = g.dt.max()
    out["backlog_max"] = g.backlog.max()
    out["flows_max"] = g.flow_count.max()

    rtt = keep(pd.read_csv(os.path.join(run, "rtt.csv")))
    rtt["phase"] = phase_of(rtt.ts, ev)
    rtt["rtt_ms"] = pd.to_numeric(rtt.rtt_ms, errors="coerce")
    out["rtt_p95"] = rtt.groupby("phase", observed=True).rtt_ms.quantile(0.95) if len(rtt) else np.nan

    # MQTT delivery on established sessions: payload "seq send_ts", line "recv_ts|topic|payload"
    mq = os.path.join(run, "mqtt_rx.log")
    if os.path.exists(mq) and os.path.getsize(mq) > 0:
        m = pd.read_csv(mq, sep="|", names=["ts", "topic", "payload"], on_bad_lines="skip")
        p = m.payload.astype(str).str.split(" ", expand=True)
        m["seq"] = pd.to_numeric(p[0], errors="coerce")
        m["sent"] = pd.to_numeric(p[1], errors="coerce")
        m = m.dropna()
        m["lat_ms"] = (m.ts - m.sent) * 1000
        m = m[m.sent >= ev.t_measure + 5]
        m["phase"] = phase_of(m.sent, ev)
        # QoS of BENIGN devices only: the telemetry of compromised sensors (botnet / poison / inject
        # bots also publish MQTT) is excluded; the all-device value is kept for transparency
        out["mqtt_lat_p95_all"] = m.groupby("phase", observed=True).lat_ms.quantile(0.95)
        bad = {"sensors/" + a for a in str(ev.attackers).split(";") if a and a != "nan"}
        m = m[~m.topic.isin(bad)]
        gm = m.groupby("phase", observed=True)
        out["mqtt_lat_p50"] = gm.lat_ms.median()
        out["mqtt_lat_p95"] = gm.lat_ms.quantile(0.95)

        def loss(d):
            s = d.groupby("topic").seq.agg(["min", "max", "count"])
            exp = (s["max"] - s["min"] + 1).sum()
            return 100 * (1 - s["count"].sum() / exp) if exp > 0 else np.nan
        out["mqtt_loss_%"] = pd.Series({ph: loss(d) for ph, d in m.groupby("phase", observed=True)})

    # new flows: ping to a device whose flow entry has expired
    sp = os.path.join(run, "setup.csv")
    if os.path.exists(sp) and os.path.getsize(sp) > 0:
        st = keep(pd.read_csv(sp, names=["ts", "dst", "setup_ms"], on_bad_lines="skip"))
        st["setup_ms"] = pd.to_numeric(st.setup_ms, errors="coerce")
        hp_ = os.path.join(run, "hosts.csv")
        if os.path.exists(hp_):               # only benign destinations measure benign service
            bad = set(pd.read_csv(hp_).query("role == 'attacker'").ip)
            st = st[~st.dst.isin(bad)]
        st["phase"] = phase_of(st.ts, ev)
        out["setup_fail_%"] = st.groupby("phase", observed=True).setup_ms.apply(lambda x: 100 * (x < 0).mean())
        out["setup_p95"] = st[st.setup_ms >= 0].groupby("phase", observed=True).setup_ms.quantile(0.95)

    # new MQTT sessions (joiners): "t0_ns,host,rc,dt_us"
    js = [f for f in glob.glob(os.path.join(run, "join_*.csv")) if os.path.getsize(f) > 0]
    if js:
        j = pd.concat(pd.read_csv(f, names=["t0", "host", "rc", "dt_us"], on_bad_lines="skip") for f in js)
        j["ts"] = j.t0 / 1e9
        j = keep(j)
        j["phase"] = phase_of(j.ts, ev)
        gj = j.groupby("phase", observed=True)
        out["join_ok_%"] = gj.rc.apply(lambda x: 100 * (x == 0).mean())
        out["join_p95_ms"] = j[j.rc == 0].groupby("phase", observed=True).dt_us.quantile(0.95) / 1000

    # defense actions and collateral damage: benign device ports restricted (block or limit)
    ap = os.path.join(run, "actions.csv")
    hp = os.path.join(run, "hosts.csv")
    if os.path.exists(ap) and os.path.exists(hp):
        a = pd.read_csv(ap).merge(pd.read_csv(hp), on=["dpid", "port"], how="left")
        a["phase"] = phase_of(a.ts, ev)
        a["benign"] = a.role != "attacker"
        for act, col in (("block", "blocks"), ("limit", "limits")):
            g_ = a[a.action == act].groupby("phase", observed=True)
            out[col] = g_.size().astype(float)
            out[col + "_benign"] = g_.benign.sum().astype(float)
        for c in ["blocks", "limits", "blocks_benign", "limits_benign"]:
            out[c] = pd.to_numeric(out[c], errors="coerce").fillna(0)
        out["collateral"] = out["blocks_benign"] + out["limits_benign"]

    out.insert(0, "scenario", ev.scenario)
    return out.round(2)


def main():
    pd.set_option("display.width", 250)
    pd.set_option("display.max_columns", 30)
    if len(sys.argv) > 2 and sys.argv[1] == "--compare":
        rows = []
        for run in sorted(glob.glob(os.path.join(sys.argv[2], "*", "*_seed*"))):
            try:
                s = summarize(run).reset_index()
                s["defense"] = os.path.basename(os.path.dirname(run))
                s["seed"] = int(run.rsplit("_seed", 1)[1])
                rows.append(s)
            except Exception as e:
                print("skip", run, e)
        df = pd.concat(rows)
        df.to_csv(os.path.join(sys.argv[2], "summary_all.csv"), index=False)
        att = df[df.phase == "attack"].groupby(["defense", "scenario"]).mean(numeric_only=True)
        cols = [c for c in ["packet_in_s", "backlog_max", "mqtt_lat_p95", "mqtt_loss_%", "setup_fail_%",
                            "join_ok_%", "join_p95_ms", "blocks", "limits", "collateral"] if c in att]
        print("\n=== Attack-phase means across seeds ===")
        print(att[cols].round(1))
        print("\nsaved:", os.path.join(sys.argv[2], "summary_all.csv"))
    else:
        print(summarize(sys.argv[1]))


if __name__ == "__main__":
    main()
