# Day 60 - Stealth scans (NULL / FIN / XMAS)

## Diagnosis first
- Model set D labels all stealth flows as udp_scan (1200/1200 offline).
  Live confidence 0.77 / 0.72: barely above the 0.70 filter.
- Hypothesis: single-packet flows, no SYN, no reply, many ports only
  resemble UDP scans in the training data.
- Signal check: 1200/1200 stealth packets flagged, 0 / 543 normal TCP packets.

## Decision
Deterministic tracker, not retraining. The signature comes from the TCP
protocol itself (legit packets carry ACK after the handshake), so it is
structural, not statistical. Dataset untouched, LOCO results stay valid.
Model udp_scan alerts are suppressed for sources the tracker already reported.

## Silent bugs found only end-to-end
1. The tracker ran but its alert was never emitted (built a string, no log).
   Unit + integration tests passed because they call the tracker directly.
2. Severity used a hardcoded "fragment" string, so the new evasion type
   was ranked LOW with no error. Fixed with EVASION_MARKERS.

## Lessons
- Detected != correctly classified: a wrong label misleads the analyst.
- A test that calls a component directly does not prove the pipeline uses it.
- Hardcoded strings in rules fail silently for new types.

## Limitations
- udp_scan suppression is per source/window: a real UDP scan from the same
  source in the same window would be hidden (unlikely, documented).