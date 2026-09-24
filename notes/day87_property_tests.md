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

## What it found
Two properties failed, and neither was a code bug: float addition loses precision
on large timestamps, so (last + elapsed) - last is not exactly elapsed. Minimal
counterexample from hypothesis: last=268435455.0, elapsed=cooldown=1.0751793617764633.
The tests now assert against the MEASURED difference and skip a 1 ms band around
the threshold - that is what the code actually promises. No consequence in practice
(real timestamps are ~1.79e9 and the thresholds are 60 s), but now it is known
rather than assumed.

## Also found, by CI rather than by hypothesis
The CI run was red while all 181 tests passed locally: an older commit was being
tested. The value of CI is exactly this - local green does not mean published green.
