# Day 70 - ACK scan (nmap -sA), 5th evasion technique

## Why it was a hole
Day 65 made the scan trackers ignore ACK-first flows (correct: ephemeral ports of
long connections). ACK scan probes are exactly ACK-first flows. Stealth tracker
ignores them too (a lone ACK is a valid flag combination).

## Diagnosis
- nmap result: <unfiltered / filtered>
- model (classify_v2): <FILL IN label and flow count>
- scan trackers (diagnose_scan_trackers): <FILL IN - expected silent>
- check_ack_scan.py: ack_scan.pcap max <FILL IN> ports per source/window;
  normal captures max <FILL IN>; threshold 10

## Signature: lone ACK probe
Initiator sends only EMPTY pure-ACK packets; the other side answers only RST or
nothing. Normal mid-connection slices always contain data or non-RST replies.
Payload length from IP/TCP headers: Ethernet padding is not payload.

## Integration
ack_scan -> family evasion, specific, MEDIUM (EVASION_MARKERS).
udp_scan suppression generalized from stealth sources to all evasion sources.

## Mutations
- replies not checked: mid-connection unit test fails
- threshold 1: below-threshold test (+ likely false positives on normal) fails

## Diagnosis
- nmap: all 200 ports filtered (router drops ACK probes, no RST)
- model: udp_scan on 400/400 flows (same confusion as stealth, day 60)
- scan trackers: old 200 FIRES -> new 0 silent (day 65 hole confirmed)
- check_ack_scan.py: ack_scan 200 ports per source/window; 0 lone ACK probes on all
  10 normal captures and on scan, stealth, dos, slowloris
- payload from headers = 0 on probes (padding not counted)

## Results
metrics: unseen 8/8 detected and correct, label shown 20/20, 177 logged / 39 notified.
Tests 107 -> 120. Only unfiltered (RST) variant untested on real data (unit test only).

## Leak found
Log still has udp_scan x2 for ack_scan.pcap. Hypothesis: suppression works only in the
window where the ACK tracker fired (>= 10 ports); edge windows reach the model's
5-flow threshold but not the tracker's. <FILL IN diagnose_campaigns result>
"Correct label" did not catch it: it checks the right label exists, not that a
wrong one is absent.