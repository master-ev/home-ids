# Day 38 - Why set C misses scan.pcap (and only scan.pcap)

## Symptom
After the direction fix, LOCO shows scan.pcap held out = 0.1% (predicted dos),
while every OTHER scan capture is 100%: decoy, decoy2_router,
scan_slow_router, scan_syn_lo.

## Why yesterday's 99.5% was misleading
With the direction bug (forward = 0), all scans looked equally "empty" on the
forward side and were grouped together. The fix made forward real, which
exposed that scan.pcap is different from the others.

## What is special about scan.pcap
ctx_src_flows ~1000, ctx_src_ports ~1000 in a single 5s window: nmap at full
speed, 1000 ports at once. Every realistic scan (rate-limited, decoys) has
6-160 flows/window. Held out, the model never saw a 1000-flow-per-window scan,
so it extrapolates toward dos (a high-volume class).

## Experiment (explain_scan_miss.py)
Thinning scan.pcap's context to a normal rate:
<PASTE RESULT HERE>

## Decision
<if volume confirmed:> Accept as a documented limitation. scan.pcap is an
unrealistically fast scan; the model correctly classifies all realistic scans.
Model locked: my_model_v2.joblib (set C, 6996 flows).

## Note on LOCO means
mean 85.8% for C is dragged down almost entirely by this one outlier and by
normal.pcap (44 flows, oldest capture). On realistic captures C is ~100%.