# Day 47 - Fifth class (UDP scan) and the DNS false positive

## UDP scan added
Two diverse captures (nmap -sU, different ranges/rates). LOCO: 95-99% held out,
no regression. First non-TCP class: TCP flag features are all 0 for UDP.

## The DNS false positive (and its fix)
With udp_scan added but no UDP *normal* traffic, real DNS was classified as DoS
(dns_normal.pcap -> dos 38/39). Same lesson as day 37's "normal" gap, now for UDP:
a new attack transport needs matching normal traffic, or the model maps unknown
normal to the nearest attack.

Fix (data + feature):
- Added normal DNS captures (to router and to 8.8.8.8) to the normal class.
- New context feature ctx_reply_rate: fraction of a source's flows in the window
  that got a reply. DNS ~1.0, scan/DoS ~0.0. check_direction confirmed: DNS 80/80
  replies, UDP scan 0.

## Set switch: C -> D
ctx_reply_rate only worked in set D (no rst/ack), not C. With DNS in the data,
rst/ack now HURT (DNS and DoS look alike on them) - the opposite of day 36, where
D was worse because rst/ack HELPED scan. Decision changed because the data changed.
D is now best across every case: mean 98.9, worst 90.9. Verified on decoy (the
original day-34 attack), scan, connect-scan, DNS, udp_scan, dos - all correct.

## Note on ctx_reply_rate vs the day-34 shortcut
Same signal (reply present) that was a harmful per-flow shortcut on day 34, here
used as a per-window context feature - and it helps instead of hurting. The
problem on day 34 was never "reply info", it was HOW it was used.