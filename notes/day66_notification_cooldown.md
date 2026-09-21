# Day 66 - Alert noise: event vs notification

## Problem
decoy.pcap: 72 port_scan alerts for ONE scan (correct label, too many).
Console noise = alert fatigue. incidents.py already compresses them for the
dashboard, so the noise is in what the human sees live.

## Why not just drop repeats
- compute_severity depends on alert counts (scan MEDIUM at 3, brute force HIGH at 5):
  dropping repeats would silently downgrade severities.
- alerts.jsonl is the evidence log for investigation.

## Design
emit_alert(): single exit point for all 7 alert sources.
- every alert is LOGGED, with notified: true/false
- NOTIFIED (printed) only once per (source, destination, kind) per 60 s;
  the next notice says "+N similar since last notice" (suppressed_repeats)
- kind is in the key: escalation (scan -> brute force) is never delayed
- clock = first packet timestamp of the window: same behaviour live and in replay

## Results
<FILL IN: decoy logged / notified, total attack alerts logged / notified>
Detected / correct label / alert kinds unchanged (log is identical).

## Mutations
- no cooldown (notify = True): repeat + decoy tests fail
- "don't log repeats" (tempting wrong design): logged-count test fails

## Limitations
- suppressed repeats are reported only at the next notice for the same key
- trackers with "already alerted" sets (slow_scan, dest_scan, fragment,
  slowloris) alert once per PROCESS LIFETIME: a second scan tomorrow from the
  same source is silent. The cooldown can replace those sets.
- slow_scan / dest_scan still use time.time(), not window time

## Results
- Attack alerts: 173 logged -> 60 notified (-65%)
- decoy.pcap: 79 logged -> 13 notified (6 sources x port_scan, 6 x slow_scan,
  1 distributed_scan): every decoy source is still shown once
- udp_scan1/2: 13 -> 3; dos: 5 -> 2
- Detected / correct label / alert kinds identical on every row
- All normal captures: 0 alerts (holdout dns_normal included)

## Next noise level (observed, not fixed)
One simple scan still gives 3 notices: port_scan + slow_scan + distributed_scan =
three detectors reporting the SAME attack. Not a cooldown problem (kind is in the
key on purpose, for escalation); needs grouping kinds into families (recon).