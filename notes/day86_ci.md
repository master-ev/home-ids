# Day 86 - Continuous integration

Tests only ever ran on my machine. Day 82 showed that 116 of 158 pass with no data
at all, so most of the suite can run on a clean runner at every push.

## What CI proves that local runs cannot
- requirements.txt actually installs everything, on an empty machine
- no hidden dependency on local files, paths or my venv
- every commit is green, not just the ones where I remembered to run the tests

## Setup
.github/workflows/tests.yml: Python 3.10, pip install -r requirements.txt,
pytest -v, then setup_check.py so the onboarding path is exercised too.
Replay tests skip there; the conftest header (day 82) explains why in the CI log.

## First run
<FILL IN: green / what broke and why>