# Day 36-37 - Data diversity, reliable captures, set C confirmed

## The key result (LOCO, % correct on the held-out capture)
scan.pcap held out:  set A 0.1%  ->  set C 99.5%
Random split stayed 0.9986 for A, B, C, D: it cannot see the difference.
=> A random split hides a model that generalizes zero.

## Chosen set: C (no backward/port features + context)
- A (bwd+port): scan -> 2002/2005 predicted dos. Shortcut wins.
- D (C minus rst/ack): 56.8% on scan. After the direction fix rst/ack are
  useful again (closed-port scan -> RST), so removing them hurt.

## Capture problems and fixes
- scapy sniff on lo in WSL returns ~0 packets. Switched to tcpdump.
- Traffic and capture were run sequentially (never simultaneous).
  Fixed with capture_run.py: tcpdump + traffic in one process.
- Mirrored-networking did not relay the Windows browser to eth1.
  Fixed by generating normal traffic FROM WSL (HTTPS requests).
- Direction fix confirmed on real data: counted backward 0 -> 73659 (dos);
  minor ~2x over-count vs real replies, does not affect set C.

## Next (day 38)
Integrate set C model into live_ids.py (context per window), live decoy test.