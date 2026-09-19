# Day 42 - Confidence scores in alerts

## What
Model-based alerts now carry predict_proba's top probability as "confidence".
predict() -> predict_proba(): the max vote share is how sure the forest is.
Aggregated: flow -> alert (mean per campaign) -> incident (mean) -> campaign.

## Rules
- Confidence is an EXTRA axis next to severity, never a filter. Low-confidence
  alerts are marked (LOW), not hidden or downgraded - a new attack the model
  has not seen may well be low-confidence.
- Rule-based detections (slow_scan, distributed_scan) have no confidence
  (None), shown as "-". None is NOT "low confidence".
- CONFIDENCE_LOW = 0.60.

## Notes
- numpy floats from predict_proba are cast to float() before json.dumps.
- Old alerts (pre-day-42, old model) have no confidence field -> "-".

## Live test
decoy (-sS -D, new IPs) -> PORT SCAN with conf ~0.9x. Correct and confident.

## Bug found and fixed
Adding the confidence print/log line left the OLD print/log line in place,
so every model-based alert was emitted twice (one without confidence, one
with). The confidence column made it visible - identical alerts had differed
only by the new field. Better observability caught a latent bug.
Fix: one print + one log_alert per campaign.