# Day 50 - Diverse DNS/UDP normal traffic

## Problem
Unseen DNS (dns_normal.pcap, not in training) classified 67% normal after
day 49. LOCO on in-dataset DNS was 97.5% - a data-coverage gap.

## Fix: 3 diverse DNS captures
- dns_div1 (76 flows): to router, query types A/AAAA/MX
- dns_div2 (148 flows): public resolvers + HTTPS mix (7779 tcp / 203 udp pkts)
- dns_div3 (121 flows): burst, 60 parallel lookups

## Result
- Unseen dns_normal.pcap: 67% -> 77% normal (30/39; 9 still dos).
- All in-dataset DNS (dns_div1/2/3, normal_dns1/2): 99-100% in LOCO.
- Attack classes intact: decoy 100%, udp 95-99%, scan 100%, dos correct.
- Set D best: mean 99.0, worst 88.6.

## Decision: accept 77%, stop here
Diminishing returns: 3 captures bought +10 points. dns_normal is one old
diagnostic file, not production; its 9 residual dos flows are isolated and
would be filtered by aggregation + trackers ("few good alerts" works at
incident level, not per-flow). Chasing 100% on one diagnostic file is not
worth more capture rounds.

## Lesson (days 37, 47, 50)
A traffic type needs DIVERSE examples, not just present ones. But also: know
when to stop. Perfect coverage of every capture is not the goal; a robust,
validated model that generalizes is.