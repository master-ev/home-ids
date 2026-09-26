# Day 100 — Retrospective

100 days, three detection paradigms, one intrusion detection system that
runs on real traffic. What I would carry into the next project:

## Lessons that repeated

- **Random splits lie; LOCO tells the truth.** 99.85% on a random split,
  0.1% on a held-out capture. Cross-validation that mirrors deployment is
  the only metric that matters.

- **Diagnose with data before fixing.** Every performance win came from a
  profiler, not a guess - including the two times my guess was wrong by an
  order of magnitude. Every bug fix started with a diagnostic script and a
  red test.

- **The wire finds what replay can't.** A SYN flood with payload passed
  undetected live; the payload-free training data never showed it. Live
  validation surfaced it, and the fix was a structural tracker, not more
  data.

- **Silent duplication hides in plain sight.** Feature set D was 43 names
  but 25 distinct for most of the project. A doubled loop, a doubled test,
  a doubled import - none crashed. A linter now guards against the class.

- **CI green is not a formality.** It caught a test that passed on my
  machine and failed on a clean clone, because it loaded a gitignored model.

## What I would do differently

- Add the linter on day 1, not day 99.
- Validate live earlier - the wire found real gaps that months of replay
  did not.
- Verify the numbers I print. "43 features" was wrong for 95 days because I
  trusted a startup message I never checked.

## What the project is

Ten attack types across three complementary layers: a Random Forest
classifier, deterministic trackers for structural and temporal attacks, and
an Isolation Forest for anomalies. Real-time on the wire (0 kernel drops
under a live flood), zero false notifications in 1.19M packets of real home
traffic, 240 tests, honest negative results documented alongside the wins.