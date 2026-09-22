# Day 74 - What is the anomaly layer worth?

## A/B on the soak holdout (second half, never trained on)
Day 73 never ran it: the "before" command was skipped and the "after" one died on a
literal <SPLIT_TIME> placeholder. soak_report refused both empty logs (day 72 guard
working as intended).
Now with --after-csv (split time read from the holdout file) and --lab-only:
- lab captures only:  <FILL IN> logged (<rate>/h), <FILL IN> notified (<rate>/h)
- + real traffic:     <FILL IN> logged (<rate>/h), <FILL IN> notified (<rate>/h)
Same packets, same pipeline, only the anomaly training data differs.

## Contribution (diagnose_anomaly_value.py)
Every attack capture replayed with and without the anomaly layer:
<FILL IN table>
Attack captures where the log changed: <FILL IN>

## Decision
<FILL IN: kept at c=0.05 as an unproven net / kept because it contributes X>
Guard test: ANOMALY_CONTAMINATION <= 0.05, raising it requires a new diagnosis.

## Lessons
- A layer that flags 89% of normal traffic carries no information.
- Measure what a component ADDS, not whether it fires: ack_scan and stealth_sX
  were at 0% before the change too - the trackers caught them, not this layer.
- Third placeholder failure of the project (<SPLIT_TIME> after day 60's two): if a
  value already exists in a file, read it from the file instead of asking for a copy.