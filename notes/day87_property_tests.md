# Day 87 - Property-based testing

172 tests, each checking one case I thought of. hypothesis generates hundreds of
inputs per property and shrinks any counterexample to the smallest failing case.

## Properties chosen
Pure functions only (labels, alert_policy, trackers): family_of never returns
empty and falls back to the kind itself; specificity is always one of two levels;
cooldown and episode boundaries are exact; labelling never crashes for any verdict
and any pair of numbers; a scan-shaped campaign is never labelled dos (the founding
bug); held_open_connections returns a subset of its input; persistent_connections
is symmetric.

## What it found
<FILL IN: nothing, or the counterexample and whether the property or the code was wrong>

## Not applied to
Stateful and I/O code (emit_alert, collect_window_alerts, load_models): property
testing fits pure functions.

