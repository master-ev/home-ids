# Day 72 - Sensor visibility and a valid soak test

## Visibility diagnosis (30 s each, eth0 in WSL2)
- tcpdump while browsing on WINDOWS: <FILL IN> packets
- tcpdump while curl runs in WSL: <FILL IN> packets
- scapy sniff (same as live_ids) with WSL curl: <FILL IN> packets
Conclusion: <FILL IN>

## Lesson
A NIDS sees only what reaches its interface (own traffic + broadcast on a switch/
Wi-Fi; real deployments use SPAN/TAP). WSL2 adds a VM layer. "What does the sensor
see?" is the first question of any deployment - it was never asked here.
A zero with an empty denominator is not a result: soak_report now refuses it,
live_ids warns after 60 s without packets.

## Offline soak
pktmon on the Windows host (--comp nics, full packets), streamed replay through
the exact live pipeline (soak_replay.py, PcapReader, window time).
- Duration: <FILL IN> h, packets <FILL IN>
- Logged: <FILL IN> (<rate>/h)   Notified: <FILL IN> (<rate>/h)
- By kind / family: <FILL IN>
- Traffic during the capture: <FILL IN>
Replay has no empty windows (live does): rates use duration, not window count.

## Privacy
*.pcapng and soak logs are gitignored: they contain all real home traffic.