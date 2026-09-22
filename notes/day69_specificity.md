# Day 69 - The most specific label reaches the human

## Problem (found on day 68)
Family grouping cut notices 60 -> 38 but hid information: udp_scan1/2 never showed
UDP SCAN, scan.pcap showed SLOW PORT SCAN (15 ports) instead of PORT SCAN (1000).
Cause: trackers emit inside the flow loop, model labels after it - the generic
tracker was always first in the window and won the family.
Lesson: optimizing one metric (notice count) silently degraded another we did not
measure (is the label informative?) -> add the metric first.

## Baseline (new column "Label shown", on day-68 code)
Expected label shown to the human: <FILL IN>/19

## Fix: two mechanisms
1. collect-then-flush per window, most specific first (stable sort):
   same-window conflicts solved with NO extra notice
2. upgrade across windows: a blocked alert passes once if more specific than
   the active notice for its key ([more specific than the earlier notice])
Generic: slow_scan, distributed_scan, suspicious. Unknown kinds = specific (fail-safe).

## Results
Label shown: <FILL IN>/19 -> 19/19. Notified 38 -> <FILL IN>. Logged/kinds unchanged.

## Mutations
- no sorting: flush unit test fails (replay still OK via upgrade, but +1 notice)
- no upgrade: cross-window unit test fails (replay still OK via sorting)
Each mechanism is guarded by its own test.

## Old tests that failed - intended change, not regression
test_same_family_detectors_notified_once and test_next_notice_lists_silent_detectors
(day 68) encoded "generic first wins". Scenario rewritten (specific first), intent
kept. An upgrade also resets the key's cooldown timer.