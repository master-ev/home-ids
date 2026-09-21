# Day 67 - Trackers that alerted once per lifetime

## Bug
slow_scan_alerted, dest_scan_alerted, frag_alerted, slowloris_alerted were latches
that never re-opened. Invisible in replay (reset per capture), fatal live: after
days of running, the IDS was blind to every attacker it had already seen.
Also: slowloris_windows summed windows forever (sporadic slow connections over
days could reach 3 windows -> false alert), and scan trackers used time.time().

## Red first (real captures, same attacker, different days, no reset)
- scan_connect_router + stealth_sX (192.168.1.236 -> .1): slow_scan 1, expected 2
- slowloris1 + slowloris_test (same triple): slowloris 1, expected 2
<FILL IN: exact failing output>

## Design: episodes (activity-based), not cooldown (notice-based)
- scan trackers: latch re-opens when the sliding 300 s history drops below threshold
- fragments / slowloris: new episode after 60 s without activity; slowloris window
  count restarts per episode
- all stateful trackers now use window time (packet timestamps)

## Gap choice (diagnose_episodes.py)
<FILL IN: longest pause inside each attack; gap 60 s = at least 2x margin>

## Mutations
- latch never re-opens: day-apart tests fail (bug back)
- no latch at all: continuous-scan test fails (log explosion guard)

## Results
metrics.md identical except the header (one episode per capture): the fix only
changes what happens BETWEEN attacks. Tests: 85 -> 93.