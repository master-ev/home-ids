# Day 56 - Tests for the deterministic trackers

## Why
5 trackers (slow scan, distributed scan, ICMP flood, Slowloris, fragmentation)
had zero tests - the most bug-prone code in live_ids.py. A test would have caught
the Slowloris server-port bug (day 53) and the ICMP double-alert (day 48).

## Refactor: trackers.py
Extracted the counting/decision logic into pure functions (no sniff, no model,
no I/O), so they can be unit-tested. Same principle as incidents.py (day 32):
decision separate from action. live_ids.py now imports and only emits alerts.
Persistence state (Slowloris window counter, alerted sets) stays in live_ids.

## Tests (8, all edge cases that bit before)
- Slowloris keys on the SERVER port regardless of packet direction (the day-53
  bug: first packet from server gave the ephemeral port -> count=1 each).
- High-traffic connections are NOT Slowloris (excludes normal web).
- Fragment threshold exact boundary; normal packet is not a fragment.
- ICMP counted per (src,dst); below threshold is silent.

34 tests total. Bugs from the past are now regression tests.