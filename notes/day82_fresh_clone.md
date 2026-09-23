# Day 82 - Fresh-clone test

Cloned the public repo into /tmp and ran the README commands with no data.

## What worked
- 8 MB clone, code only
- setup_check.py lists missing files AND the script that builds each, including
  why captures cannot be shared
- correlate.py and dashboard.py report a missing alerts.jsonl instead of crashing
- metrics_report.py stops with the require_file message pointing at setup_check.py
- 116 of 158 tests pass with no captures, models or alert logs

## What was missing
- requirements.txt (dependencies were only in my head and my venv)
- the 42 skips were unexplained: added a pytest header saying replay tests need
  captures

## Lesson
Testing the system is not the same as testing the project. Everything an outsider
touches first - install, first command, first error message - had never been run
from a clean state.