# Day 73 - Anomaly false positives on real traffic

## First valid soak (day 72 capture, 0.49 h, 542517 packets)
27 alerts logged (55.2/h), 14 notified (28.6/h) - ALL anomaly, all false.
Unusable rate. What worked: honest "anomaly" label (day 63), LOW severity,
cooldown 27 -> 14 (day 66/68). The system was wrong transparently.

## Diagnosis
- 20/27 alerts came from the machine's IPv6 address (ISP + Cloudflare);
  lab normal captures are IPv4 to the router. IPv6 share of soak flows: <FILL IN>
- every alert says "N unusual flows, 1 ports": browsers open many parallel
  connections to one CDN host on 443; normal_web.pcap has 48 TCP packets total
- Fifth time the same lesson: a traffic type must be IN the data, diverse.
  This time the fix is data I already have: the soak capture IS real normal traffic.

## Configuration (diagnose_soak_anomalies.py, flagged flows)
<FILL IN table: lab only vs lab+soak at 0.05 / 0.01 / 0.005, on holdout and attacks>
Chosen: <FILL IN>

## Honest evaluation
Time split of the soak capture: first half trains, second half is holdout.
Time split, not random: flows of one browsing session are correlated.
Holdout notified: <BEFORE>/h -> <AFTER>/h. Attack captures: <unchanged?>

## Limitations
- Training the "normal" model on unlabelled real traffic: no attack was run during
  the capture and the classifier flagged nothing, but external hostile traffic
  cannot be excluded. One short known session; model and trackers untouched.
- The capture comes from one host on one network, one evening.