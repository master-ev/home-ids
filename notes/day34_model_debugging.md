# Day 34 - Why a decoy scan was classified as DoS

## Symptom
Night of 2026-09-16, 01:01:11: six alerts "DoS FLOOD (20 flows)" from
10.0.0.1-5 and 192.168.1.236 to 192.168.1.1, each with num_ports = 10,
all within 3 ms. This was an `nmap -D` decoy scan, not a flood.

## Hypotheses and evidence
- H1 (flows look alike individually): partly. A scan probe against a
  *filtered* port gets no reply, and in the training data DoS/brute-force
  flows also have zero backward packets.
- H2 (timing shortcut): rejected. No timing feature in the top 10 (MDI).
- H3 (aggregation rule): confirmed. `if num_ports > 10` -> 10 ports failed,
  the next rule (`model says dos and flows > 10`) fired. Classic > vs >= bug.
  20 flows on 10 ports = nmap retransmitting probes to filtered ports.
- H4 (window context separates the classes): confirmed. Attempts per port:
  scan 1.0, decoy 1.7-1.8, DoS 747-2115 on a single port.

## Top features (saved model)
pkt_len_mean, bwd_bytes, bwd_pkt_len_mean, fwd_pkt_len_mean, fwd_pkt_len_max,
total_bwd_packets. Class means: bwd_bytes = 0 for dos and bruteforce,
54 for scan (RST replies).

## Other findings
- Random split accuracy 99.85% is meaningless: flows from one capture are
  near-duplicates.
- Permutation importance = 0 for every feature: features are redundant
  (several encode "no backward traffic"), so removing one changes nothing.
- decoy.pcap: 720 packets = 60 ports x 6 sources x 2 tries, zero replies.
- Only 44 "normal" flows in the dataset.

## Conclusion
The model learned a lab artifact: "no backward traffic = attack".
DoS/brute-force were captured on `lo` (same IP on both ends), so backward
traffic is missing or miscounted. A scan of filtered ports produces the
same signature. Fix: context features + removing shortcut features,
validated on a held-out capture (day 35).