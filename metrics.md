# Home IDS - Metrics

Generated 2026-09-25 02:21 at commit `63b2a1a` (+ uncommitted changes) by `metrics_report.py`.

> **How to read this.** Each capture is replayed through the live pipeline
> (`live_ids.analyze_window`: model + 0.70 filter + aggregation + trackers).
> *Detected* = at least one alert. *Correctly labelled* = an alert of the expected kind.
> Captures marked *in training* were seen by the model, so for them this measures
> the pipeline, not generalization. Model generalization = LOCO (below).
> *Logged* = alerts written to the log (evidence, used by incidents.py).
> *Notified* = alerts shown to the human (one per source/destination/family per cooldown).
> *Label shown* = the expected label appears in the console, not only in the log.
> *Wrong in log* = logged labels that do not describe the capture (end up in incidents).

## Summary

- **Unseen attack captures**: detected 11/11, correctly labelled 9/11
- **In-training attack captures**: detected 12/12, correctly labelled 12/12
- **Attack alerts**: 180 logged, 45 notified (cooldown 60 s per source/destination/family)
- **Expected label shown to the human**: 21/23 attack captures
- **Attack captures with wrong labels in log**: 0/23
- **Normal captures with any alert**: 0/10 (0 alerts total)

## Attack captures

| Capture | Expected | In training | Detected | Correct label | Label shown | Wrong in log | Logged | Notified | Shown kinds | Alert kinds |
|---|---|---|---|---|---|---|---|---|---|---|
| scan.pcap | port_scan | yes | yes | yes | yes | - | 4 | 2 | distributed_scan x1, port_scan x1 | distributed_scan x1, port_scan x2, slow_scan x1 |
| bruteforce.pcap | brute_force | yes | yes | yes | yes | - | 1 | 1 | brute_force x1 | brute_force x1 |
| dos.pcap | dos | yes | yes | yes | yes | - | 4 | 1 | dos x1 | dos x4 |
| decoy.pcap | port_scan | yes | yes | yes | yes | - | 79 | 7 | distributed_scan x1, port_scan x6 | distributed_scan x1, port_scan x72, slow_scan x6 |
| scan_syn_lo.pcap | port_scan | yes | yes | yes | yes | - | 3 | 2 | distributed_scan x1, port_scan x1 | distributed_scan x1, port_scan x1, slow_scan x1 |
| scan_slow_router.pcap | port_scan | yes | yes | yes | yes | - | 5 | 2 | distributed_scan x1, port_scan x1 | distributed_scan x1, port_scan x3, slow_scan x1 |
| scan_connect_router.pcap | port_scan | yes | yes | yes | yes | - | 5 | 2 | distributed_scan x1, port_scan x1 | distributed_scan x1, port_scan x3, slow_scan x1 |
| decoy2_router.pcap | port_scan | yes | yes | yes | yes | - | 16 | 4 | distributed_scan x1, port_scan x3 | distributed_scan x1, port_scan x12, slow_scan x3 |
| udp_scan1.pcap | udp_scan | yes | yes | yes | yes | - | 13 | 2 | distributed_scan x1, udp_scan x1 | distributed_scan x1, slow_scan x1, udp_scan x11 |
| udp_scan2.pcap | udp_scan | yes | yes | yes | yes | - | 13 | 2 | distributed_scan x1, udp_scan x1 | distributed_scan x1, slow_scan x1, udp_scan x11 |
| syn_flood1.pcap | syn_flood | yes | yes | yes | yes | - | 4 | 1 | syn_flood x1 | syn_flood x4 |
| syn_flood2.pcap | syn_flood | yes | yes | yes | yes | - | 4 | 1 | syn_flood x1 | syn_flood x4 |
| stealth_sX.pcap | stealth_scan | no | yes | yes | yes | - | 4 | 2 | distributed_scan x1, stealth_scan x1 | distributed_scan x1, slow_scan x1, stealth_scan x2 |
| stealth_sN.pcap | stealth_scan | no | yes | yes | yes | - | 4 | 2 | distributed_scan x1, stealth_scan x1 | distributed_scan x1, slow_scan x1, stealth_scan x2 |
| stealth_sF.pcap | stealth_scan | no | yes | yes | yes | - | 4 | 2 | distributed_scan x1, stealth_scan x1 | distributed_scan x1, slow_scan x1, stealth_scan x2 |
| frag_scan.pcap | fragmented_scan | no | yes | yes | yes | - | 1 | 1 | fragmented_scan x1 | fragmented_scan x1 |
| frag_normal.pcap | port_scan | no | yes | yes | yes | - | 4 | 2 | distributed_scan x1, port_scan x1 | distributed_scan x1, port_scan x2, slow_scan x1 |
| slowloris1.pcap | slowloris | no | yes | yes | yes | - | 1 | 1 | slowloris x1 | slowloris x1 |
| slowloris_test.pcap | slowloris | no | yes | yes | yes | - | 1 | 1 | slowloris x1 | slowloris x1 |
| ack_scan.pcap | ack_scan | no | yes | yes | yes | - | 2 | 1 | ack_scan x1 | ack_scan x2 |
| srcport_scan.pcap | port_scan | no | yes | yes | yes | - | 4 | 2 | distributed_scan x1, port_scan x1 | distributed_scan x1, port_scan x2, slow_scan x1 |
| padded_100.pcap | port_scan | no | yes | no | no | - | 2 | 2 | distributed_scan x1, slow_scan x1 | distributed_scan x1, slow_scan x1 |
| padded_200.pcap | port_scan | no | yes | no | no | - | 2 | 2 | distributed_scan x1, slow_scan x1 | distributed_scan x1, slow_scan x1 |

## Normal captures (false alerts)

Since day 63 the IsolationForest is trained on the scenario normal captures,
so for them this is in-sample. `dns_normal.pcap` is held out.

| Capture | Alerts | Notified | Alert kinds |
|---|---|---|---|
| normal.pcap | 0 | 0 | - |
| normal_web.pcap | 0 | 0 | - |
| normal_stream.pcap | 0 | 0 | - |
| normal_mixed.pcap | 0 | 0 | - |
| normal_dns1.pcap | 0 | 0 | - |
| normal_dns2.pcap | 0 | 0 | - |
| dns_div1.pcap | 0 | 0 | - |
| dns_div2.pcap | 0 | 0 | - |
| dns_div3.pcap | 0 | 0 | - |
| dns_normal.pcap | 0 | 0 | - |

## Tests

```
210 passed in 93.09s (0:01:33)
```

## LOCO (model generalization, last lines)

```
normal_mixed.pcap       normal         100.0   100.0   100.0   100.0
normal_stream.pcap      normal         100.0   100.0   100.0   100.0
normal_web.pcap         normal         100.0   100.0   100.0   100.0
scan.pcap               scan           100.0   100.0   100.0    99.9
scan_connect_router.pcapscan           100.0   100.0   100.0   100.0
scan_slow_router.pcap   scan           100.0   100.0   100.0   100.0
scan_syn_lo.pcap        scan            99.4    99.4    99.4    99.4
syn_flood1.pcap         syn_flood        0.5   100.0   100.0   100.0
syn_flood2.pcap         syn_flood      100.0   100.0   100.0   100.0
udp_scan1.pcap          udp_scan        95.6    95.6    95.6    95.6
udp_scan2.pcap          udp_scan        99.4    99.4    99.4    99.4
mean                                    93.8    99.1    99.0    99.1
worst                                    0.5    88.6    88.6    88.6
Results below 80%: what did the model say?
set A  syn_flood1.pcap          true=syn_flood   predicted={'udp_scan': 210, 'syn_flood': 1}
```

