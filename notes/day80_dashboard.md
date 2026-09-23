# Day 80 - Dashboard brought up to date

Untouched since day 59; the pipeline gained families (68), notified/suppressed
(66-68), model_unsure (79) and two new kinds (ack_scan, anomaly).

## Added
- detection source per incident, derived from existing fields: confidence None =
  tracker, verdict "anomaly" = anomaly layer, otherwise model with its confidence
- model-unsure badge (day 79 signal)
- alerts vs notified, so the noise reduction is visible
- family distribution and a status banner with the soak false-positive rate
- legend explaining incident vs campaign for readers of the README screenshot

## Deliberately not shown
Raw alerts: showing all 180 would rebuild the noise removed on days 66-69.
They stay in alerts.jsonl for investigation.

## Compatibility
Alerts logged before day 66 have no 'notified' field: treated as notified.

## Bug found while wiring the dashboard
The new helpers read alert["model_verdict"] / ["notified"], but incidents.load_alerts
normalizes alerts to {src, dst, type, time, confidence, raw} - the original dict is
in "raw". The unit tests passed because they used flat dicts, not the real format.
Fixed with raw_of() and two tests that use the load_alerts shape.
Same class of bug as day 61: tests that do not use the real data format.

## Demo log
build_demo_alerts.py replays one capture per family through the current pipeline:
36 alerts -> 13 incidents -> 2 campaigns, 9 tracker / 6 model incidents,
2 "model unsure" badges. alerts.jsonl holds test history from before the day 75-79
fixes, so it is not what the README should show.