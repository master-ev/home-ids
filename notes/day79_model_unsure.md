# Day 79 - When the model goes silent, say so

## From day 78
padded_100 / padded_200: model udp_scan at 0.36 / 0.34 (reference: scan at 1.00),
trackers 200 ports FIRES. Detected 11/11, but Label shown dropped 21/21 -> 21/23.

## Fix
A campaign filtered out by the 0.70 confidence filter is remembered per (src, dst)
and attached to that window's tracker alerts: field model_unsure and console suffix
[model unsure: udp_scan 0.36]. No extra alert, no weaker filter.
Low model confidence WITH firing trackers is itself an evasion signal
(out-of-distribution detection, free from the confidence we already compute).

## Decision
No retraining for padding - see day78 note.

## Known limitation
Tracker alerts report the port count at threshold crossing (15), not the total (200).