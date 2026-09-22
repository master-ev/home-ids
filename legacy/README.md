# Legacy / archived scripts

These are earlier steps kept for history. They are **not** part of the current
pipeline — see the main README for what is active.

## CICIDS2017 phase (abandoned — domain gap)
- `explore.py`, `prepare.py` — load and prepare the public CICIDS2017 dataset
- `build_model.py`, `build_model_matched.py` — models trained on CICIDS features
- `train.py`, `predict.py`, `compare.py` — early training/eval experiments

A model trained on CICIDS did not detect my own attacks (features computed
differently — the "domain gap"). The fix was to build my own labeled dataset;
see `build_my_dataset.py` / `train_mine.py` in the main folder.

## Early capture/flow experiments (superseded)
- `sniff.py` — first packet sniffer
- `flows.py`, `build_table.py` — first flow grouping and table building
  (folded into `features.py`)

## Old per-attack captures (superseded by capture_run.py)
- `capture_brute.py`, `capture_dos.py`, `capture_decoy.py` — captured on `lo`
  with scapy; replaced by `capture_run.py` (tcpdump + simultaneous traffic).

## Moved on day 76 (replaced, kept for history)
- anomaly.py, detect.py, classify_mine.py: first detection prototypes, replaced by
  live_ids.py (windowed pipeline, trackers, campaign labels).
Removed from trackers.py: slowloris_candidates, replaced on day 75 by
held_open_connections + persistent_connections (handshake + persistence).