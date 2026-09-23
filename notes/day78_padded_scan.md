# Day 78 - Padded scan (nmap --data-length): attacking the ML layer

## Why
Every other evasion so far attacked the trackers. Padding attacks the MODEL: all
size features (mean, total, deviation) move far from the training distribution
(54-byte probes). A cheap, real-world version of an adversarial example.

## Diagnosis (check_padding.py)
| capture | payload bytes | model verdicts | mean conf | tracker ports |
|---|---|---|---|---|
| padded_100 | <FILL IN> | <FILL IN> | <FILL IN> | <FILL IN> |
| padded_200 | <FILL IN> | <FILL IN> | <FILL IN> | <FILL IN> |
| scan_connect_router (reference) | <FILL IN> | scan | <FILL IN> | 400 |

## Result
<FILL IN: which layer failed, which held>

## Decision
<FILL IN: retrained / documented as a model limitation because the trackers catch it>

## Layered defence, tested
This is the first capture that attacks the ML layer directly. <FILL IN what it proves>