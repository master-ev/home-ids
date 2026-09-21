# Day 61 - End-to-end pipeline tests

## Why
Day 60: the stealth tracker detected scans but the alert was never written.
Unit + integration tests passed because they called the tracker directly:
they tested the component, not the wiring into live_ids.

## What
tests/test_pipeline.py replays saved captures through live_ids.analyze_window,
split into WINDOW_SECONDS windows by packet timestamp (like sniff(timeout=...)),
and checks what actually lands in the alert log.
- reset_live_state() clears tracker memory between tests
- monkeypatch redirects ALERT_LOG to a tmp file (real alerts.jsonl untouched)

## Mutation testing results
| Mutation | Tests that failed |
|---|---|
| stealth alert not emitted (day 60 bug) | replay_logs_stealth_alert, logged_stealth_alert_gets_medium_severity |
| udp_scan suppression removed | replay_suppresses_udp_scan_label |

Offline replay: model still labels the XMAS scan udp_scan at conf 0.72 / 0.81,
so the suppression test guards a real behavior.

## Rule going forward
Every new tracker gets: a unit test + a replay test that checks the alert log.

## Refactor
compute_severity: hardcoded "flood"/"slowloris" and a duplicated DoS check
replaced by HIGH_IMPACT_MARKERS. Severity tests green before and after.
Lesson: before a refactor, save `correlate.py > before.txt` and diff after.