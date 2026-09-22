# Day 71 - Soak test on real home traffic + wrong-label metric

## Wrong labels in log (metrics.md)
"Correct label" only checks the right label EXISTS. Day 70 leaked udp_scan next to
ack_scan and the column still said yes. New column: logged kinds that do not describe
the capture (acceptable = expected kind + slow_scan/distributed_scan on scans).
First result: <FILL IN, expected ~3/20: slowloris on syn_flood1/2 and dos>

## Soak test
- Setup: live_ids.py --log soak_day71.jsonl, session file with windows/packets,
  NO attacks during the run -> every alert is a false positive by construction
- Duration: <FILL IN> h, windows <FILL IN> (expected ~720/h), packets <FILL IN>
- Logged: <FILL IN> (<rate>/h)   Notified: <FILL IN> (<rate>/h)
- By kind / family: <FILL IN>
- Traffic during the run: <browsing / streaming / updates / phones ...>

## Findings
<FILL IN per notified alert type: which detector, which traffic, hypothesis>

## Privacy
The soak log holds real device and service IPs: gitignored, only aggregates published.