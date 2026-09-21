# Day 62 - Metrics: detected vs correctly labelled

## Summary
- Unseen attacks: 4/4 detected, 4/4 correct (stealth x3, fragmentation)
- In-training attacks: 12/12 detected, 10/12 correct
- Normal: 3/9 captures with alerts, 8 alerts, all from IsolationForest on DNS

## Findings (hypotheses, not yet verified)
1. dos.pcap -> suspicious / port_scan. Model says dos (0.97-0.99), but the
   campaign rules check num_ports before the dos rule, and dos requires <= 3
   ports. Same-IP capture probably inflates num_ports with ephemeral ports.
2. decoy.pcap -> suspicious x72. Model says scan (1.00), but rate-limited
   decoys give < 10 ports per source per window, so port_scan never fires.
   Trackers still catch it. 72 alerts for one scan = too noisy.
   Root cause of 1+2: aggregation labels by port count, ignores model verdict.
3. DNS normal -> BRUTE FORCE (model: anomaly). IsolationForest is fitted only
   on normal.pcap (no DNS): domain gap. And an anomaly-only campaign gets a
   concrete attack label from its shape (many flows, 1 port -> brute_force).
Minor: slowloris tracker also fires on SYN floods (half-open looks slow).

## Not covered
ICMP flood: no saved capture, tracker only verified live.