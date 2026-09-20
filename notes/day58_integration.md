# Day 58 - __main__ guard and end-to-end tests

## Guard
Model loading + Isolation Forest training were at module level, so `import
live_ids` ran everything (and after day 57's require_file, could sys.exit).
Moved into load_models(), called from run_live() under `if __name__ ==
"__main__"`. Now importable with no side effects - which is what let the
integration test run analyze_window directly.

## Integration tests (tests/test_integration.py)
Feed a saved capture through analyze_window window-by-window, redirect log_alert
to a list, assert the right alert kinds appear. Skips on a fresh clone (no
model). First tests that exercise the whole pipeline, not isolated functions.

## Bug caught by the integration test (and it was a real one)
analyze_window had `if not flows: return` early. Fragments give
get_ips_ports=None, so an all-fragments window had empty flows and returned
BEFORE the fragment tracker ran - a pure `nmap -f` scan window was silently
skipped, live too. It only worked live because windows had mixed traffic.
Unit tests passed (fragment_alerts works in isolation); only the end-to-end
test saw that analyze_window never called it. Fix: packet-level trackers
(fragment, ICMP) run first, before the flows check.

## Layered testing pays off
unit tests catch function logic; integration tests catch how functions connect.