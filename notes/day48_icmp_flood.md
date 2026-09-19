# Day 48 - Sixth attack: ICMP flood (as a tracker, not an ML class)

## Why not an ML class
ICMP has no ports, so flow_key groups ALL icmp between two IPs into ONE flow
(port 0 for everything). 4000 flood packets -> 1 flow. A class cannot be learned
from 1-2 data points; LOCO reported a meaningless 100% on a single sample, and
adding it regressed normal_dns1 (context poisoned).

## Decision: deterministic tracker
An ICMP flood is raw volume, not a subtle pattern - perfect for a threshold
rule, like the slow-scan and distributed-scan trackers. "Straturi
complementare": ML for the hard cases (scan vs dos vs udp), rules for the
obvious ones (thousands of pings).

## What was needed
- get_ips_ports extended to parse ICMP (port 0), so ICMP is no longer invisible.
- live_ids sniff filter: "tcp or udp" -> "tcp or udp or icmp".
- ICMP flows EXCLUDED from the ML loop (continue on proto == ICMP), else they
  hit no if-branch -> UnboundLocalError, and got double-reported via anomaly.
- New per-(src,dst) ICMP counter; alert when >= ICMP_FLOOD_THRESHOLD (100/window).
- compute_severity: "flood" -> HIGH.

## Bugs caught by live testing (not unit tests)
- A pure-ICMP window (zero campaigns) crashed: the campaign-alert emission had
  drifted OUTSIDE its loop when the ICMP block was inserted, so `data` was
  undefined. Only a 100%-ICMP window exposed it.

## Refinement noted (not done)
Flood is reported twice: echo requests (src->router) and echo replies
(router->src). Same incident, two lines. Could filter to ICMP type 8 (request)
only. correlate.py groups them into one campaign anyway.