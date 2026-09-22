# Day 71 - Soak test on real home traffic + wrong-label metric

## Wrong labels in log (metrics.md)
"Correct label" only checks the right label EXISTS. Day 70 leaked udp_scan next to
ack_scan and the column still said yes. New column: logged kinds that do not describe
the capture (acceptable = expected kind + slow_scan/distributed_scan on scans).
First result: <FILL IN, expected ~3/20: slowloris on syn_flood1/2 and dos>

## Soak test - FIRST ATTEMPT INVALID
live_ids.py --log in WSL: 75 windows (6 min), 0 PACKETS, 0 alerts.
Zero observations, not zero false positives. The first version of soak_report.py
printed 0.00/h without any warning - the tool was wrong too.
Diagnosis and a valid soak: see day 72.

## Findings
<FILL IN per notified alert type: which detector, which traffic, hypothesis>

## Privacy
The soak log holds real device and service IPs: gitignored, only aggregates published.