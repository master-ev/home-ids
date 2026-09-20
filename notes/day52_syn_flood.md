# Day 52 - Seventh class: SYN flood

## The challenge
SYN flood sits between existing classes: like a SYN scan (SYN, no handshake)
and like DoS (hammers one port). Distinguishing signature:
- vs scan: ctx_src_ports = 1 (one port) vs many; ctx_flows_per_port high vs ~1
- vs dos: ctx_reply_rate = 0 (raw SYN, no reply) vs 0.996 (real HTTP server)
- vs udp_scan: is_tcp = 1 vs 0

## Verified before capturing
check_synflood.py simulated the flow shape first (lesson from ICMP: don't
capture data for a class the model can't distinguish). Signature was distinct,
so it went ahead as an ML class (unlike ICMP, which became a tracker).

## Result
LOCO set D: syn_flood1 100%, syn_flood2 100% held out. No regression - all
other classes 99-100%. Set D best ever: mean 99.1, worst 88.6.
reply_rate confirmed on real capture: syn_flood 0.000, dos 0.996.

## Integration
live_ids: SYN FLOOD alert (model says syn_flood + many flows + few ports).
incidents: HIGH severity - the existing "flood" rule already covers syn_flood.

## Note
It worked on the first try (no diagnostic saga) because the lessons were applied
upfront: 2 diverse captures, reuse of existing features (reply_rate, is_tcp,
src_ports), verify-before-capture. Contrast with scan.pcap (day 40) and ICMP
(day 48).

## Cosmetic note
Alerts show source 0.0.0.0: synflood.py uses send() with IP(dst=...) only,
so scapy/kernel fills the source and it shows as 0.0.0.0 in the capture.
Detection is unaffected; setting IP(src=...) explicitly would fix the label.