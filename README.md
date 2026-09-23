# Home IDS

A network intrusion detection system for my own home network: three detection
layers (Random Forest, deterministic trackers, anomaly detection), 9 attack types,
5 evasion techniques tested, and - the part I care about most - every claim below
measured against traffic the system had never seen.

**0 false notifications in 1.19 million packets of real home traffic.**
**11/11 unseen attack captures detected.** 158 tests, 85% coverage.

![Dashboard](docs/dashboard.png)

## The story: 99.85% that meant nothing

The first model scored 99.85% on a random train/test split. In production it
labelled a decoy scan as a DoS flood. Leave-One-Capture-Out evaluation - training
on every capture except one, testing on that one - gave **0.1%** on the unseen
scan.

Three causes, all found by diagnosing with data instead of guessing:
- a shortcut: "no reply = attack", learned from captures where only attacks went
  unanswered
- a direction bug: flow direction decided on IP alone, not (IP, port)
- missing diversity: the model had learned the fingerprint of each capture, not
  the behaviour

The fixes (context features, an explicit `is_tcp` feature, direction on (IP, port),
diverse captures across sources, tools and protocols) took set D to a LOCO mean of
~99%. Every number in this README is measured the same way: on captures the model
never saw, replayed through the exact live pipeline.

## Architecture

Traffic is captured in 5-second windows and grouped into flows. Each window goes
through three independent layers:

| Layer | What it does | Where it fails |
|---|---|---|
| **Random Forest** (feature set D, 43 features) | labels each flow: scan, udp_scan, dos, brute force, SYN flood | size-based features: a padded scan drops it to conf 0.34 |
| **Deterministic trackers** | temporal and structural patterns the model cannot see in one window: slow scans, distributed scans, ICMP floods, Slowloris, fragmentation, NULL/FIN/XMAS flags, ACK probes | nothing that needs statistics |
| **Anomaly detection** (IsolationForest) | flows unlike anything in the normal traffic it was trained on | see below |

Model alerts below 0.70 confidence are dropped: a model that is unsure must not
put a label on something. Since day 79 the fact that it was unsure is attached to
the tracker alerts of that window - low confidence plus firing trackers is itself
an evasion signal.

Alerts are then aggregated: alerts → incidents (same source, type, time window) →
campaigns (multi-source, multi-stage), with severity and aggregated confidence.
The dashboard shows incidents and campaigns, never raw alerts.

### The third layer, measured

The anomaly layer is meant to catch what the other two have never seen. Measured
on real traffic and on unseen attacks:

| | real normal traffic (holdout) | ack_scan | stealth_sX |
|---|---|---|---|
| trained on lab captures only | **89.2%** of flows flagged | 0% | 0% |
| + real-traffic flows | 2.6% | 0% | 0% |

Trained on lab captures alone it flagged almost all real traffic (28.6 false
notices/hour in the first valid soak). On the two genuinely unseen attacks it
flagged nothing, before or after: the deterministic trackers caught them. Replaying
all 23 attack captures with and without the layer changed the log on **zero** of
them.

It is kept as a net for the unknown, at a contamination level diagnosed against a
held-out half of real traffic, and its detection value is documented as **unproven
rather than claimed**.

## Evasion techniques

| Technique | Result |
|---|---|
| Timing (slow scan) | defended: per-source tracker |
| Decoys (`nmap -D`) | defended: per-destination tracker + explicit `is_tcp` |
| Fragmentation (`nmap -f`) | defended: packet-level fragment tracker (evaded completely at first) |
| Flag anomalies (NULL/FIN/XMAS) | defended: structural signature (RFC 793) |
| ACK scan (`nmap -sA`) | defended: lone-ACK-probe tracker |
| Source-port spoofing (`nmap -g 53`) | **tested, not an evasion here** - direction comes from the probe, not from port numbers |
| Padding (`--data-length`) | **the model fails** (udp_scan at conf 0.34); the trackers catch it; the alert says the model was unsure |

## Method

Every fix in this project followed the same loop: **diagnose with data, then fix -
never guess**. A diagnostic script before every change (`diagnose_*.py`, 8 of them),
a failing test that reproduces the bug, the fix, a mutation that proves the test
guards it, and a before/after measurement in `metrics.md`.

Three bugs in this project were wiring bugs: the logic was right, the connection
was missing, and no test checked the output ([day 60](notes/), [day 65](notes/),
[day 70](notes/)). Each one added a test at the layer where it slipped through.

### Four questions, not one

Most IDS projects report one number: did it detect the attack? This one measures
four, because days 60-79 showed they are different questions.

| Question | Result |
|---|---|
| **Detected?** any alert at all | 11/11 unseen, 12/12 in-training |
| **Correctly labelled?** the right kind is in the log | 9/11 unseen, 12/12 in-training |
| **Label shown?** the right kind reaches the console, not just the log | 21/23 |
| **Wrong labels in log?** labels that do not describe the capture | **0/23** |

The two captures missing *Label shown* are the padded scans: the model falls below
the confidence filter, the trackers catch the scan, and the console shows
`SLOW PORT SCAN ... [model unsure: udp_scan 0.34]` instead of `PORT SCAN`. The
attack is detected and the analyst is told the classifier could not label it.

### Noise

**180 alerts logged, 45 notified.** Every alert is written to `alerts.jsonl` -
`incidents.py` needs the full evidence, since severity depends on alert counts.
Only the first per (source, destination, family) within 60 seconds is shown to the
human, and the next notice lists which detectors stayed silent. One decoy scan went
from 79 console lines to 7, with every one of its six sources still reported.

158 tests · 82% coverage on the core modules · 40 dated engineering notes ·
123 commits

### False positives on real traffic

Lab captures of a few minutes are not evidence. The system was measured against
two captures of real home traffic (taken on the Windows host with `pktmon`,
replayed through the exact live pipeline), no attacks running, so every alert is a
false positive by construction:

| | duration | packets | notified |
|---|---|---|---|
| held-out half of capture 1 | 0.41 h | 381,467 | **0** |
| capture 2, fully unseen, another part of the day | 0.54 h | 810,224 | **0** |

Before the normal-traffic data was added to the anomaly model, the same held-out
half produced 14.5 false notifications per hour.

The first attempt at this measurement produced 75 windows and **0 packets**: the
sensor in WSL2 saw none of the Windows host's traffic. Zero observations is not
zero false positives, and the reporting tool now refuses such a session
([day 72](notes/day72_sensor_visibility.md)).

## Engineering notes

`notes/` holds 40 dated notes, one per working session: the diagnosis that preceded
each change, the hypotheses that data rejected, the mutations that proved a test
guards what it claims, and the decisions not to fix something. A few that show the
method:

- [day 60](notes/day60_stealth_scans.md) - detected is not the same as correctly labelled
- [day 63](notes/day63_anomaly.md) - the anomaly layer flagged 89% of real normal traffic
- [day 72](notes/day72_sensor_visibility.md) - a soak test that measured nothing, and why
- [day 74](notes/day74_anomaly_value.md) - measuring what a whole layer adds: zero
- [day 77](notes/day77_source_port_scan.md) - an evasion technique that turned out not to be one

## Limitations

- **Sensor placement**: a NIDS sees only what reaches its interface. On a switched
  network that is its own traffic plus broadcast; real deployments use a SPAN port
  or a TAP. The soak captures were taken on the Windows host for this reason.
- `lo` cannot be captured in WSL, so the DoS and brute-force captures come from a
  single source and are not LOCO-validated.
- **ACK scan probes are ignored by the scan trackers** since day 65 (they are
  ACK-first flows). A dedicated tracker covers them; `nmap -sA` is detected, but
  the general port trackers are blind to ACK-only probes.
- `slowloris_triple` uses `min(sport, dport)` as the server port: wrong under
  `nmap -g 53` when the scanned port is above 53. Harmless today (Slowloris needs a
  completed handshake and persistence), pinned by a test that documents it.
- The anomaly layer's detection value is unproven (see above).
- The soak measurements come from one host on one network, on two evenings.
- The v1 model (`my_model.joblib`) is a fallback for `USE_V2 = False` and is not
  loaded in normal operation.
- Tracker alerts report the port count at the moment the threshold was crossed
  (15), not the final total (200).

## Running it

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/python setup_check.py          # what is present and what needs building

sudo venv/bin/python live_ids.py        # live, on the auto-detected interface
venv/bin/python correlate.py            # alerts -> incidents -> campaigns
venv/bin/python dashboard.py            # writes dashboard.html

venv/bin/python metrics_report.py --all # regenerate metrics.md (replay + tests + LOCO)
```

Captures, models and alert logs are gitignored: `setup_check.py` lists what to
build and which script builds it.