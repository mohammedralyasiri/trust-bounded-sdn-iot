"""Free-text notice runs: review latency, LLM verdicts, first offload, block attempts. usage: freetext.py RESULTS_DIR DEF [DEF..]"""
import json, sys, glob, os, statistics as S
import pandas as pd
root = sys.argv[1]
for d in sys.argv[2:]:
    lat, rows = [], []
    for r in sorted(glob.glob(os.path.join(root, d, '*free_seed*'))):
        ev = pd.read_csv(r + '/events.csv').iloc[0]
        crowd = set(open(r + '/crowd.txt').read().split()) if os.path.exists(r + '/crowd.txt') else set()
        hosts = pd.read_csv(r + '/hosts.csv'); ip2h = dict(zip(hosts.ip, hosts.host))
        rev = []
        for l in open(r + '/gov_log.jsonl'):
            x = json.loads(l)
            try: rv = json.loads(x['raw']).get('reviews', [])
            except Exception: rv = []
            for y in rv: rev.append((x['t'], y))
        L = [y['review_latency_s'] for _, y in rev if y['error'] is None]
        lat += L
        trust = sum(1 for _, y in rev if isinstance(y['judgement'], dict) and y['judgement'].get('trust_notices'))
        sel = [json.dumps((y['judgement'] or {}).get('devices')) for _, y in rev if isinstance(y['judgement'], dict)][:1]
        ga = pd.read_csv(r + '/gov_actions.csv')
        off = ga[(ga.action == 'offload') & (ga.verdict == 'ok')]
        offh = {ip2h.get(i) for i in off.ip}
        first = round(off.ts.min() - ev.t_start, 1) if len(off) else None
        blk = ga[ga.action == 'block']
        notice = open(r + '/notice.txt').read().strip()[:40] if os.path.exists(r + '/notice.txt') else ''
        rows.append(dict(run=os.path.basename(r), reviews=len(rev), trusted=trust, errors=sum(1 for _, y in rev if y['error']),
                         lat_med=round(S.median(L), 1) if L else None, first_off_s=first,
                         off_crowd=len(offh & crowd), off_other=len(offh - crowd), crowd=len(crowd),
                         block_req=len(blk), block_ok=int((blk.verdict == 'ok').sum()), sel=sel[0][:60] if sel else '', notice=notice))
    print('\n##', d, ' review latency median %.1f s (min %.1f, max %.1f, n=%d)' % (S.median(lat), min(lat), max(lat), len(lat)) if lat else '')
    print(pd.DataFrame(rows).to_string(index=False))
