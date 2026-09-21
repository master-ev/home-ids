# Day 65 - Scan trackers counted ephemeral ports

## Problem
slow_scan / distributed_scan fired on dos.pcap, slowloris1, slowloris_test,
sometimes reversed (router -> attacker). Trackers take (src, dst, dport) from the
first packet of each flow in a 5 s window; for long connections that packet is
often a server reply, so dport = the client's ephemeral port.

## Diagnosis (diagnose_scan_trackers.py)
<FILL IN: per capture, old -> new max ports per pair / per dst, and how many
ephemeral dports came from ACK-first flows>

## Options considered
A. ignore ephemeral ports       -> evasion hole (scan only 49152-65535)
B. lower port = server          -> ambiguous when both ports are high
C. count a TCP flow only if its first packet has no ACK  <- chosen
   RFC 793: after the opening SYN every packet carries ACK. Probes
   (SYN, NULL, FIN, XMAS) never do, whatever port they target.

## Result
<FILL IN: metrics diff - which tracker alerts disappeared, scans unchanged>
Mutation (counts_as_scan_probe -> always True): reply test + slowloris replay fail.

## Known limitations
- nmap ACK scan (-sA) sends ACK-only probes: no longer counted by the scan trackers.
  Candidate for its own tracker (like stealth, day 60).
- UDP keeps first-packet orientation (no flags); no false alerts measured on DNS.
- dos.pcap still raises a slowloris alert: an HTTP flood does hold many slow
  connections; left as is, to be reviewed.

## Diagnosis (diagnose_scan_trackers.py)
Ephemeral dports came only from ACK-first flows:
- dos.pcap: 44 of 352 ACK-first flows, 0 in probe-first. slow_scan 45 -> 1
- slowloris1: 400 of 440 ACK-first, 0 in probe-first. 40 -> 1
- slowloris_test: 300 of 330 ACK-first, 0 in probe-first. 30 -> 1
All TCP scans unchanged (scan 1855, scan_slow 300, scan_connect 400,
decoy 60, decoy2 151, frag_normal 200, stealth 200). Normals unchanged.

## Result
metrics.md: slow_scan + distributed_scan removed from dos, slowloris1,
slowloris_test; every scan keeps them; detected / correct label unchanged.