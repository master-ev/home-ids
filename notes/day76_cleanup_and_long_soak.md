# Day 76 - Evidence-based cleanup and an independent long soak

## Dead code, found with evidence
audit_usage.py: references outside the defining file; coverage: lines actually run.
Kept on purpose: diagnose_*/check_* scripts (they ARE the method), attack generators
(reproducibility), ML experiments (README numbers), setup_check.py (new users).

Removed:
- trackers.slowloris_candidates + its 3 unit tests (replaced day 75). The valuable
  idea of one of them - direction-independent triple - is now tested on
  live_ids.slowloris_triple.
- my_model.joblib is no longer required or loaded while USE_V2 is true.
Moved to legacy/: <FILL IN>

Coverage of the core modules: <FILL IN>

## Independent long soak
soak_day76.pcapng: <FILL IN> h, <FILL IN> packets, another part of the day, no part
of it used for training.
Logged <FILL IN> (<rate>/h), notified <FILL IN> (<rate>/h). By kind: <FILL IN>

## Regression check
metrics.md unchanged after the cleanup - the only criterion that matters for a refactor.
Tests 143 -> 141 (3 removed with their dead function, 1 added).