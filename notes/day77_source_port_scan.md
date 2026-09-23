# Day 77 - Source-port scan (nmap -g 53): a NEGATIVE result

## Hypothesis
Direction and "server port" are decided by port number in several places, so a
privileged source port could invert direction and blind the port trackers.

## Diagnosis (check_srcport.py) - hypothesis REJECTED
srcport_scan: 210 TCP flows, all with source port < 1024; 200 ports probed;
trackers see 200 distinct dports; model: scan 200/200; slow_scan and dest_scan FIRE.
Reference scan_connect_router: 400 probed, 400 seen.

## Why the design held
dport comes from the FIRST packet of the flow - the scanner's probe - not from
comparing port numbers (day 1: direction decided on (IP, port)); and since day 65
only no-ACK probe flows feed the scan trackers. The technique was covered before
it was tried.

## Remaining assumption
slowloris_triple uses min(sport, dport) as the server port: wrong under -g 53,
harmless today (slowloris needs handshake + persistence). Pinned by a test that
documents it rather than approving it.

## Kept as evidence
srcport_scan.pcap is now an unseen attack capture in metrics.md: detected,
correctly labelled, label shown.