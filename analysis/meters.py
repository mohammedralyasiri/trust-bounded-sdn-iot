import sys, re, os, glob, csv, collections, statistics as st
def parse(path):
    S = collections.defaultdict(dict)      # (sw, meter) -> {t: (in, drop)}
    cur = None
    for line in open(path):
        if line.startswith('#'): continue
        parts = line.split(None, 2)
        if len(parts) < 3: continue
        t, sw, rest = float(parts[0]), parts[1], parts[2]
        m = re.match(r'meter:(\d+) .*packet_in_count:(\d+)', rest)
        if m:
            cur = (sw, int(m.group(1)), t, int(m.group(2))); continue
        m = re.match(r'0: packet_count:(\d+)', rest.strip())
        if m and cur and cur[0] == sw and cur[2] == t:
            S[(cur[0], cur[1])][t] = (cur[3], int(m.group(1))); cur = None
    return S
def run(d):
    hosts = list(csv.DictReader(open(os.path.join(d, 'hosts.csv'))))
    ev = next(csv.DictReader(open(os.path.join(d, 'events.csv'))))
    role = {('s%s' % h['dpid'], int(h['port'])): h['role'] for h in hosts}
    S = parse(os.path.join(d, 'meters.log'))
    rate = collections.defaultdict(float)   # t -> passed pps over fast-path fwd meters of attackers
    rate_all = collections.defaultdict(float)
    permeter = []
    for (sw, mid), ser in S.items():
        if not 2000 <= mid < 3000: continue
        port = mid - 2000
        ts = sorted(ser)
        for a, b in zip(ts, ts[1:]):
            (i0, d0), (i1, d1) = ser[a], ser[b]
            if i1 < i0: continue            # meter recreated
            p = ((i1 - d1) - (i0 - d0)) / (b - a)
            off = (i1 - i0) / (b - a)
            k = round(b)
            rate_all[k] += p
            if role.get((sw, port)) == 'attacker': rate[k] += p
            permeter.append((p, off))
    c = int(open(os.path.join(d, 'meters.log')).readline().split('OFF_PPS=')[1].split()[0])
    t0, t1 = float(ev['t_start']), float(ev['t_end'])
    att = [v for k, v in rate.items() if t0 + 40 <= k <= t1]
    allv = [v for k, v in rate_all.items() if t0 + 40 <= k <= t1]
    pm = max((p for p, _ in permeter), default=0)
    off = max((o for _, o in permeter), default=0)
    return dict(c=c, bot_peak=max(att, default=0), bot_mean=st.mean(att) if att else 0,
                all_peak=max(allv, default=0), meter_max=pm, offered_max=off, n=len(S))
if __name__ == '__main__':
    root = sys.argv[1]
    for d in sorted(glob.glob(os.path.join(root, 'sr_p*', '*_seed*'))):
        try: r = run(d)
        except Exception as e: print(d, 'ERR', e); continue
        print('%-32s c=%3d bot_mean=%7.0f bot_peak=%7.0f all_peak=%7.0f per_meter_max=%6.1f offered_max=%6.0f'
              % (d.split('results_full/')[1], r['c'], r['bot_mean'], r['bot_peak'], r['all_peak'], r['meter_max'], r['offered_max']))
