# Day 59 - Refinements

## Silent import (fix)
Day 58's guard was incomplete: dead module-level init (load_normal + anomaly
training + a "Live IDS running on None" print) still ran at import. Removed it;
moved anomaly training into load_models() where it belonged. `import live_ids`
is now fully silent, no side effects. run_live() detects the interface and loads
models at startup only.

## Documented, not fixed (diminishing returns)
- SYN flood alerts show source 0.0.0.0: scapy L3 send lets the kernel fill the
  source. Detection unaffected; a test-tool quirk.
- Unseen DNS ~77%: one old diagnostic file; in-dataset DNS is 99-100% and
  aggregation filters isolated false positives. Not worth more capture rounds.

## Judgement
Chose to document two low-impact issues rather than spend a day chasing marginal
gains at 59/100. Knowing when to stop is part of the work.