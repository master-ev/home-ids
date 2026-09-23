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