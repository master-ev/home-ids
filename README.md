# Home IDS — Machine-Learning Intrusion Detection for a Home Network

A real-time intrusion detection system for my own home network. It captures live
traffic, groups it into flows, and combines three complementary layers: a
**Random Forest classifier** for known attack types, deterministic **trackers**
for high-volume or multi-source patterns, and an **Isolation Forest** for
anomalies. Detections are aggregated into incidents and campaigns, scored by
severity and model confidence, and shown on a live dashboard.

Everything is tested against my own infrastructure, with attacks I generate
myself against my own target — no abstract benchmark data.

## What it detects

- **Port scans (TCP)**, including evasive variants: slow scans (timing), decoy
  scans (`nmap -D`), distributed scans (many sources, one target), and both
  connect (`-sT`) and SYN (`-sS`) scans
- **UDP scans** (`nmap -sU`)
- **DoS** (flood against my own server)
- **Brute-force** (repeated login attempts against my own server)
- **ICMP flood** (ping flood — caught by a deterministic tracker, not the model)
- **Anomalies** — traffic that does not match learned normal behaviour

## How it works — three complementary layers

Security is layers, each covering the others' blind spots:

| Layer | Handles | Why |
|---|---|---|
| Random Forest classifier | scan / udp_scan / dos / bruteforce / normal | subtle per-flow + per-window patterns |
| Deterministic trackers | slow scan, distributed scan, ICMP flood | obvious volume/multi-source cases a rule catches better |
| Isolation Forest | unknown anomalies | what neither of the above was trained for |

The ML model does the hard discrimination; rules handle what is plainly a matter
of thresholds (thousands of pings, ports touched over time). Raw alerts are then
aggregated → correlated into incidents → grouped into campaigns → prioritised by
severity **and** model confidence, so the output is few good alerts, not noise.

## The story behind the model

The interesting part of this project is not "I trained a Random Forest". It is
what happened when I evaluated it honestly.

An early model reported **99.85% accuracy** and looked perfect. In production it
raised a **false "DoS FLOOD"** on what was actually a decoy port scan. When I
switched from a random train/test split to **leave-one-capture-out** evaluation
(hold out a whole capture, train on the rest), that same model scored **0.1%**
on a scan it had never seen — it classified nearly every scan flow as DoS.

The random split had hidden real problems: a **shortcut** (the model learned
"no reply traffic = attack", an artifact of capturing DoS on `lo`), a
**flow-direction bug** (direction decided by IP alone, wrong when both ends
share an IP), and a **data-diversity gap** (each attack captured one way, so the
model learned the capture's fingerprint — interface, tool, speed — not the
behaviour).

The fixes were features and data, not model tricks: per-window **context
features** (ports per source, flows per port, reply rate), an explicit
**`is_tcp`** feature (protocol was implicit in flag counts and got diluted),
correcting the direction, and adding **diverse captures** across sources, tools,
and protocols. The result classifies every realistic attack type at ~95–100% on
held-out captures, validated by leave-one-capture-out rather than a misleading
random split.

Recurring lessons, written up in [`notes/`](notes/):

- A random split can hide a model that generalizes to zero. Hold out whole
  captures instead.
- A traffic type needs *diverse* examples, not just present ones — this bit
  three times (normal traffic, then UDP, then DNS).
- A signal the model needs should be an *explicit* feature; left implicit, it
  gets diluted by richer features.
- Every features change invalidates old evaluation results — re-run it.

## Pipeline

capture (tcpdump / scapy)
-> flows + rich features + per-window context (features.py, context.py)
-> Random Forest (set D) + trackers + Isolation Forest (live_ids.py)
-> alerts with confidence (alerts.jsonl)
-> incidents -> campaigns, severity + confidence (incidents.py, correlate.py)
-> live dashboard (dashboard.py --watch)


## Running it

Requires Python 3.10, run inside WSL (Ubuntu). Capture needs `sudo`.

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt

# run the test suite (26 tests)
venv/bin/python -m pytest -v

# live IDS (writes alerts to alerts.jsonl); interface is auto-detected
sudo venv/bin/python live_ids.py

# live dashboard, in another terminal (regenerates + auto-refreshes)
venv/bin/python dashboard.py --watch      # then open dashboard.html

# correlate the alert log into incidents and campaigns
venv/bin/python correlate.py
```

The active network interface is detected automatically (`net_iface.py`), because
under WSL mirrored networking it changes between sessions.

## Repository layout

Active pipeline is in the root. Earlier experiments (the abandoned CICIDS2017
phase, first capture/flow prototypes, superseded capture scripts) are archived
in [`legacy/`](legacy/) with their own README — kept for history, not part of
the current system.

## Known limitations

- **`lo` is not capturable in this WSL setup** (tcpdump and scapy both return 0
  packets), so DoS and brute-force use single captures and are not
  leave-one-capture-out validated. Documented, not hidden.
- **ICMP flood is rule-based, not ML**: ICMP has no ports, so all packets between
  two hosts collapse into one flow — too few data points to learn a class. A
  volume threshold is the right tool, and it lives alongside the other trackers.
- **Unseen DNS ~77%**: on a DNS capture not in training, a few flows are still
  misclassified. In-dataset DNS is 99–100%; isolated per-flow false positives are
  filtered by aggregation into incidents.

## Screenshots

![Live dashboard](docs/dashboard_1.png)
![Incidents and campaigns](docs/dashboard_2.png)

## Design philosophy

- A good IDS produces **few good alerts**, not many noisy ones: aggregate →
  correlate → prioritise, by severity *and* model confidence.
- A model is only as good as how representative its training data is.
- Security is complementary layers: classifier, trackers, and anomaly detector
  each cover the others' blind spots.
- Heuristic detection flags suspicion, it does not prove intent.