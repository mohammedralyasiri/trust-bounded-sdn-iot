#!/usr/bin/env python3
"""
Re-implementation of the port-level, zero-training LLM detector of Swileh & Zhang (2026, Expert Systems
with Applications): every 10 s each switch port's counters (received packets / bytes, transmitted packets /
bytes) over the last 10 s are written as one few-shot prompt with ten labelled benign examples; the LLM
answers a single digit (1 = DDoS). A flagged port gets a drop rule in the controller and is re-enabled 30 s
after its last flag (see telemetry_switch.py, DEFENSE=llmport).

Differences from the paper, forced by the testbed: the model is the same local Qwen2.5 3B used by our governor
(the paper's best model, DeepSeek-v3, is a hosted model); the ten benign examples are drawn from this run's
own pre-attack windows; ports are classified one prompt at a time, as in the paper, so on a 96-port network a
round may take longer than the 10-s window - its real duration is logged.

usage: llmport.py RUN_DIR  |  llmport.py --selftest selftest.json
"""
import json
import os
import random
import sys
import time
import urllib.request

RUN = sys.argv[1] if len(sys.argv) > 1 else "."
MODEL = os.environ.get("LLMPORT_MODEL", "qwen2.5:3b")
OLLAMA = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
WIN = 10.0
CAL_WINDOWS = 3                      # pre-attack windows used to draw the ten benign examples

# prompt template of Swileh & Zhang (2026), Fig. 2: task, ten labelled benign interface states, the new state, instruction
INSTR = ("[Task]: Detect whether the interface status over the last ten seconds represents a flood-based DDoS attack (1) "
         "or Normal traffic (0). Analyze the labeled examples below and classify the new interface status.\n"
         "[Labeled interface status]:\n")
FINAL = "[Instruction]: Only answer with one number: 0 if Normal, or 1 if DDoS. Do not explain."


def prompt_for(examples, w):
    shots = "".join("- " + line(e) + " 0\n" for e in examples)
    return INSTR + shots + "[New interface status]:\n- " + line(w) + " ???\n" + FINAL


def verdict(ans):
    """first 0/1 digit in the answer; anything else counts as no flag"""
    for ch in ans:
        if ch in "01":
            return ch
    return "?"


def line(d):
    rp, rb, tp, tb = d
    return "(Received %d packets with %d bytes and sent %d packets with %d bytes) =>" % (rp, rb, tp, tb)


def ask(prompt):
    body = json.dumps(dict(model=MODEL, prompt=prompt, stream=False, keep_alive="30m",
                           options=dict(temperature=0, seed=1, num_predict=4, num_ctx=2048, num_thread=4)))
    req = urllib.request.Request(OLLAMA + "/api/generate", data=body.encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r).get("response", "")


def read():
    try:
        return json.load(open(os.path.join(RUN, "port_counters.json")))
    except Exception:
        return None


def main():
    rnd = random.Random(1)
    log = open(os.path.join(RUN, "llmport_log.jsonl"), "a")
    flags, examples, cal, n_win = {}, [], [], 0
    prev = None
    while prev is None or not prev["ports"]:
        time.sleep(1)
        prev = read()
    t_next = time.time() + WIN
    while True:
        time.sleep(max(0.0, t_next - time.time()))
        cur = read()
        t_next = time.time() + WIN
        if not cur:
            continue
        p0 = {(a[0], a[1]): a[2:] for a in prev["ports"]}
        scale = WIN / max(1.0, cur["t"] - prev["t"])   # a slow round must not inflate the 10-s counts
        wins = {}
        for a in cur["ports"]:
            k = (a[0], a[1])
            if k in p0:
                wins[k] = [int(round(max(0, x - y) * scale)) for x, y in zip(a[2:], p0[k])]
        prev = cur
        n_win += 1
        if n_win <= CAL_WINDOWS:
            cal.extend(w for w in wins.values() if w[0] > 0)
            if n_win == CAL_WINDOWS:
                examples = rnd.sample(cal, min(10, len(cal)))
                log.write(json.dumps(dict(t=time.time(), examples=examples)) + "\n")
            continue
        t0, n_flag, n_err, votes = time.time(), 0, 0, {"0": 0, "1": 0, "?": 0}
        for k, w in sorted(wins.items()):
            try:
                v = verdict(ask(prompt_for(examples, w)))
            except Exception:
                v, n_err = "?", n_err + 1
            votes[v] += 1
            if v == "1":
                flags["%d:%d" % k] = time.time()
                n_flag += 1
                tmp = os.path.join(RUN, ".llmport.tmp")
                with open(tmp, "w") as f:
                    json.dump(dict(flags=flags), f)
                os.replace(tmp, os.path.join(RUN, "llmport_flags.json"))
        log.write(json.dumps(dict(t=round(t0, 2), round_s=round(time.time() - t0, 2), ports=len(wins),
                                  flagged=n_flag, errors=n_err, votes=votes)) + "\n")
        log.flush()
        t_next = max(t_next, time.time())


def selftest(path):
    """offline check before a campaign: benign interface states recorded in earlier runs (pre-attack windows) and
    flood-like states at the rates of our attackers (~105-byte packets); prints how many of each the model flags"""
    d = json.load(open(path))
    rnd = random.Random(1)
    ben = d["benign"]
    shots, held = ben[:10], rnd.sample(ben[10:], min(60, len(ben) - 10))
    att = d["attack"]
    res = {}
    for name, rows in (("benign", held), ("attack", att)):
        v = [verdict(ask(prompt_for(shots, w))) for w in rows]
        res[name] = dict(n=len(v), flagged=v.count("1"), unparsed=v.count("?"))
    print(json.dumps(dict(model=MODEL, **res)))


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--selftest":
        selftest(sys.argv[2])
    else:
        main()
