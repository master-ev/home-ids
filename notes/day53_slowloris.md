# Day 53 - Slowloris: persistent tracker + confidence filter

## Why a tracker, not an ML class
Slowloris is temporal: connections held open over minutes. As an ML class it
failed LOCO 0% (only 61 flows, 2 captures; slowloris2 was killed by the router).
It also *is* conceptually a DoS, so the model puts it there. Like ICMP flood and
slow scan: temporal attack -> deterministic tracker.

## Signature (per 5s window)
Many concurrent TCP connections to one server port, each with little traffic,
persistent across windows. Threshold: >=20 connections, <=12 pkts each, >=3
consecutive windows.

## Bug: port from packet direction
Live, the first packet of a flow in a window was often the router's reply, so
get_ips_ports()[3] gave the ephemeral client port, not 80. Each connection got
a unique key -> count=1 each. Fix: key on the SERVER port (min of sport/dport)
and a normalized IP pair, so all connections aggregate on (a, b, 80).
Same class of direction bug as days 34-38.

## Noise fix: confidence filter
Slowloris flows also hit the ML pipeline, which saw 40 ephemeral ports and
cried "PORT SCAN / dos" at conf ~0.5 every window. Added
MODEL_ALERT_MIN_CONFIDENCE = 0.70: model alerts below it are dropped as noise;
rule-based detections (confidence None) always pass. Real scans (conf ~1.0)
still fire. Closes the loop on day-42 confidence: from triage info to active
filter. "Few good alerts."