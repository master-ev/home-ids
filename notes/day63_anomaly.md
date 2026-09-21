# Day 63 - IsolationForest false alarms on normal traffic

## Diagnosis (diagnose_anomaly.py, % of flows flagged)
- Baseline (normal.pcap only, c=0.15): 27-67% on the other normal captures,
  15.9% on normal.pcap itself (= contamination, by construction).
  Domain gap, not only DNS: web/stream/mixed were also 27-33%.
- All normal captures, leave-one-capture-out:
  c=0.15 still 13-24% on several captures; c=0.05 <= 6.1% on 8/9;
  c=0.01 0% everywhere but also 0% on slowloris1 (detector goes blind).
- Chosen: all normal captures, c=0.05. Holdouts: dns_normal 2.6%, frag_normal 0%.
  slowloris1 stays 100%.

## Surprises
- normal.pcap left out -> 75% flagged (25% even at c=0.01): its traffic type
  exists in no other capture. Each normal traffic type lives in ONE capture.
- Homogeneous captures (stealth_sX, frag_normal: 400 near-identical flows)
  flip 0% <-> 100%: effectively one data point, not evidence about contamination.
- frag_scan.pcap = 0 flows: fragments have no ports, invisible to both models.
  Confirms why fragmentation is a packet-level tracker.

## Fixes
1. Anomaly model trained on every normal capture in scenarios.py, c=0.05.
2. choose_campaign_label(): anomaly-only campaigns are labelled "anomaly"
   (LOW/MEDIUM by count), never brute_force by shape.
   Fix 1 lowers the rate; fix 2 keeps the label honest when it still fires.

## Limitations
- normal.pcap's traffic type is uncovered by other captures (need more diverse normal data).
- Normal-capture rows in metrics.md are in-sample for the anomaly model now.