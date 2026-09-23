# Day 83 - Splitting live_ids.py

683 lines doing seven things: capture, features, model, trackers, labelling,
notification, session handling.

## Moves
- labels.py: pure campaign-labelling rules (day 64). Went through first try -
  pure functions are a clean cut.
- flow_state.py: sliding port histories and episode latches of the scan trackers.
  Took two rounds: moving STATE means four kinds of reference (definition, use,
  reset, tests), and leftovers in reset_live_state and the two call sites broke
  53 tests at once.

live_ids.py: 683 -> <FILL IN> lines.
Success criterion: metrics.md unchanged and 158 tests green. Both held.

## Postponed: alert_policy.py
emit_alert writes through ALERT_LOG, which is reassigned from outside in replay.py,
soak_replay.py and two test fixtures - 12 references in 5 files. Moving state plus
an externally-patched module global deserves its own day.

## Lesson
Pure functions move cleanly; state does not. Before moving state, grep for every
reference and expect the reset path and the tests to need updating too.

## Day 84: alert_policy.py

Moved: families, specificity, cooldown, episodes, emit_alert, flush_window_alerts.

ALERT_LOG stayed in live_ids.py. Moving it would have meant updating 12 references
in 5 files, including three that reassign it from outside (replay.py,
soak_replay.py, two fixtures) - and a missed one would silently write to the real
alerts.jsonl while the tests still passed.
Instead emit_alert takes the log function as a parameter: no external reference
changes, and the policy module now has no I/O dependency of its own.

live_ids.py: 683 -> 611 -> <FILL IN> lines.
Coverage per module: <FILL IN>