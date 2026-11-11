#!/usr/bin/env python3
"""
Offline replay of governor decisions on recorded controller snapshots (gov_states.jsonl).

For every recorded round the backend (an LLM through Ollama, or the rule-based governor) is asked
again; its directives are checked by the same verifier rules as in the controller (V1-V6, from the
recorded evidence) and scored against the ground truth of the run (hosts.csv roles, crowd.txt).

usage: gov_replay.py RUN_DIR [RUN_DIR ...] --backend ollama:qwen2.5:7b [--repeat 3] [--out f.json]
Per backend it reports: latency, valid-JSON rate, offload precision/recall on legitimate crowd
devices, blocks proposed against clean devices (and how many the verifier stopped), etc.
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import governor as G            # noqa: E402  (prompt, parsing and backends are shared)


def truth(run):
    roles = {}
    for ln in open(os.path.join(run, "hosts.csv")).read().splitlines()[1:]:
        h, ip, _, _, role = ln.split(",")
        roles[ip] = (h, role)
    crowd = set()
    p = os.path.join(run, "crowd.txt")
    if os.path.exists(p):
        names = set(open(p).read().split())
        crowd = {ip for ip, (h, _) in roles.items() if h in names}
    attackers = {ip for ip, (h, r) in roles.items() if r == "attacker"}
    return crowd, attackers


def verify(a, st, n_ok, n_off):
    devs = {d["ip"]: d for d in st["devices"]}
    t, ip = str(a.get("type", "")).lower(), str(a.get("ip", ""))
    if t not in ("offload", "release", "block"):
        return "V6"
    d = devs.get(ip)
    if d is None:
        return "V6"            # not in the snapshot: unknown / quiet device (controller would check live)
    sp = d["foreign_source_share"]
    if n_ok >= st["budgets"]["max_directives"]:
        return "V4"
    if t in ("offload", "release") and sp >= 0.05:
        return "V2"
    if t == "block" and sp < 0.5:
        return "V3"
    if t == "offload" and not d["offloaded"] and n_off >= st["budgets"]["max_offloaded"]:
        return "V4"
    return "ok"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("runs", nargs="+")
    ap.add_argument("--backend", default="rulegov")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    agg = dict(backend=a.backend, rounds=0, valid=0, latency=[], off_tp=0, off_fp=0, off_fn=0,
               block_clean=0, block_clean_passed=0, block_att=0, release_att=0, release_att_passed=0,
               rejected={}, examples=[])
    for run in a.runs:
        crowd, att = truth(run)
        for line in open(os.path.join(run, "gov_states.jsonl")):
            rec = json.loads(line)
            st, feed = rec["state"], rec["feed"]
            active = {d["ip"] for d in st["devices"] if d["distinct_destinations"] >= 5 or d["offloaded"]}
            for _ in range(a.repeat):
                t0 = time.time()
                G.BACKEND = a.backend
                try:
                    ans, raw, _, _, cl, nt = G.decide(st, feed)
                    acts = G.expand(ans, st, cl, nt) if isinstance(ans, dict) else None
                except Exception as e:
                    ans, raw, acts = None, repr(e), None
                agg["latency"].append(time.time() - t0)
                agg["rounds"] += 1
                if not isinstance(acts, list):
                    agg.setdefault("invalid_log", []).append(dict(run=os.path.basename(run), seq=st["seq"],
                                                                  latency=round(time.time() - t0, 1), raw=str(raw)[:500]))
                    continue
                agg["valid"] += 1
                n_ok = n_off = 0
                proposed_off = set()
                for x in acts:
                    if not isinstance(x, dict):
                        continue
                    v = verify(x, st, n_ok, n_off)
                    t, ip = str(x.get("type", "")).lower(), str(x.get("ip", ""))
                    if v != "ok":
                        agg["rejected"][v] = agg["rejected"].get(v, 0) + 1
                    else:
                        n_ok += 1
                    if t == "offload":
                        proposed_off.add(ip)
                        n_off += v == "ok"
                    if t == "block":
                        if ip in att:
                            agg["block_att"] += 1
                        else:
                            agg["block_clean"] += 1
                            agg["block_clean_passed"] += v == "ok"
                    if t == "release" and ip in att:
                        agg["release_att"] += 1
                        agg["release_att_passed"] += v == "ok"
                want = crowd & active
                agg["off_tp"] += len(proposed_off & want)
                agg["off_fp"] += len(proposed_off - crowd)
                agg["off_fn"] += len(want - proposed_off)
                agg.setdefault("rounds_log", []).append(dict(run=os.path.basename(run), seq=st["seq"],
                                                         latency=round(time.time() - t0, 1), judgement=ans,
                                                         n_actions=len(acts), raw=str(raw)[:300]))
    L = sorted(agg["latency"]) or [0]
    tp, fp, fn = agg["off_tp"], agg["off_fp"], agg["off_fn"]
    agg.update(latency_mean=round(sum(L) / len(L), 2), latency_p95=round(L[int(0.95 * (len(L) - 1))], 2),
               valid_rate=round(agg["valid"] / max(1, agg["rounds"]), 3),
               offload_precision=round(tp / (tp + fp), 3) if tp + fp else None,
               offload_recall=round(tp / (tp + fn), 3) if tp + fn else None)
    del agg["latency"]
    print(json.dumps({k: v for k, v in agg.items() if k not in ("examples", "rounds_log")}, indent=1))
    if a.out:
        json.dump(agg, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
