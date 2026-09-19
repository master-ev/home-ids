# Day 43 - Confidence in the dashboard: two-axis triage

## What
Incident and campaign tables now have a Conf column (model confidence as %).
Low-confidence detections (< 0.60) get a grey "review" badge next to severity
and a "To review" count card. Rule-based detections show a dash (no score).

## Design choices
- One axis = one visual channel: severity uses color, confidence uses a badge
  that appears ONLY when low. Absence of the badge means "fine", so the eye
  jumps straight to what needs checking.
- Sorting stays severity + time. Confidence is shown, never used to reorder:
  a low-confidence alert may be a new attack and must not sink in the list.
- Two-axis triage: HIGH+confident = act; HIGH+unsure = check urgently;
  LOW+confident = known noise; LOW+unsure = review lightly.

## Note
Current real data has no low-confidence detections (scans at 100%), so the
badge was verified with a temporary conf=0.42 test alert, then removed.