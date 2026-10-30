#!/usr/bin/env python3
"""The operator's rounds between two times, from arcad's log on standard
input, one JSON line each: operator-tests.sh's load test.

    rounds.py FROM TO INTERVAL < arcad.log

Each log line is led by its time: an epoch with a fraction, or an ISO time
(journalctl -o short-iso-precise). A round is the line arcad writes when it
broadcasts one ("round N (txid): … participation(s), … vB"). With the round
interval INTERVAL in seconds, `after_tick_s` is how long after its timer's
tick the round went out: the ticks fall at a fixed phase, taken from the
quickest round, so the figure is the build time above that round's own.
"""
import datetime
import json
import re
import sys

t0, t1, interval = float(sys.argv[1]), float(sys.argv[2]), float(sys.argv[3])
pat = re.compile(r"round (\d+) \(([0-9a-f]{64})\): (\d+) batch\(es\), (\d+) offboard\(s\), (\d+) participation\(s\), "
                 r"\d+ order\(s\) filled, (\d+) vB")
out = []
for line in sys.stdin:
    m = pat.search(line)
    if not m:
        continue
    first = line.split()[0]
    try:
        t = float(first)
    except ValueError:
        try:
            t = datetime.datetime.fromisoformat(first).timestamp()
        except ValueError:
            continue
    if t0 <= t <= t1:
        out.append({"round": int(m.group(1)), "at": t, "batches": int(m.group(3)), "participations": int(m.group(5)),
                    "vbytes": int(m.group(6))})
if interval > 0 and out:
    phase = [r["at"] % interval for r in out]
    base = min(phase)
    for r, p in zip(out, phase):
        r["after_tick_s"] = round(p - base, 3)
for r in out:
    print(json.dumps(r))
