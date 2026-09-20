# Day 57 - Runnable by others

## Problem
On a fresh clone, generated files (model, captures, dataset) are gitignored and
absent, so live_ids.py crashed with a bare FileNotFoundError. Bad first
impression for anyone opening the repo.

## setup_check.py
Checks packages, code files (in git), and generated files (local). If the model
is missing, prints the exact build steps. Honest about the real limitation:
captures are personal traffic and gitignored, so the model can't be reproduced
without capturing your own traffic - the code/tests/pipeline are all present.

## live_ids.py
require_file() gives a clear message + pointer to setup_check instead of a
traceback when the model or normal.pcap is missing.