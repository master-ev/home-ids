# Day 55 - Fragmentation evasion (adversarial loop)

## The evasion
nmap -sS -f fragments IP packets into 8-byte pieces. get_ips_ports does
`if TCP in packet` - a fragment has no complete TCP layer, so it returns None
and the pipeline skips it. Result: ALL fragments ignored.

## Confirmed with data
frag_scan.pcap: 1202 packets, 1200 fragmented, get_ips_ports_ok = 0.
Live: nmap -sS -f produced ZERO alerts. A scan with -f was completely invisible.
frag_normal.pcap (no -f): 400 flows, all caught as scan. So it was the
fragmentation, not the scan, that evaded.

## Fix: detect fragmentation itself as the signal
Not reassembly (complex; incomplete fragments defeat it anyway). Instead: normal
traffic almost never fragments; a burst of tiny fragments to one target is
anomalous by definition. Tracker: >= 30 fragmented packets from one source per
window -> FRAGMENTED SCAN. Same pattern as ICMP flood / Slowloris: a volumetric
signal a rule catches better than the per-flow model.

## Result
nmap -sS -f now -> FRAGMENTED SCAN (180 fragments). Normal scan still PORT SCAN
conf 1.00. Normal traffic silent. Severity MEDIUM (evasive recon).

## Evasion techniques tested and defended: 3
timing (slow scan), decoys (nmap -D), fragmentation (nmap -f). Fragmentation was
the only one that evaded completely on first test - which makes the fix the most
convincing demonstration.