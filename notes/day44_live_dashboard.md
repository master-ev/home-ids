# Day 44 - Live dashboard with auto-refresh

## What
dashboard.py --watch regenerates dashboard.html every 10s in a loop, and the
page carries an HTML meta-refresh so the browser reloads itself. Left open
next to live_ids.py, campaigns appear and grow in near real time.

## Two halves, both needed
1. Regenerate the file: --watch loop (while True + sleep), like live_ids.py.
2. Reload in the browser: <meta http-equiv="refresh" content="N">.
Both on the same interval so they stay in sync.

## Design choices
- meta-refresh, not JavaScript/fetch: no server, one line, works from a local
  file. Simplest tool that solves it.
- Refresh is opt-in (refresh_seconds param, 0 = static). A one-off dashboard
  for README/sharing must not reload forever. Same idea as USE_V2 flag.
- Loop, not cron: start/stop manually with Ctrl+C, nothing configured in the
  system.

## Chain now fully live
live_ids.py writes alerts -> dashboard.py --watch regenerates ->
browser meta-refresh reloads. End to end, hands-off.