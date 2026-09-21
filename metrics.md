# Home IDS - Metrics

Generated 2026-09-22 00:56 at commit `a110e9c` (+ uncommitted changes) by `metrics_report.py`.

> **How to read this.** Each capture is replayed through the live pipeline
> (`live_ids.analyze_window`: model + 0.70 filter + aggregation + trackers).
> *Detected* = at least one alert. *Correctly labelled* = an alert of the expected kind.
> Captures marked *in training* were seen by the model, so for them this measures
> the pipeline, not generalization. Model generalization = LOCO (below).

## Summary

- **Unseen attack captures**: detected 7/7, correctly labelled 7/7
- **In-training attack captures**: detected 12/12, correctly labelled 12/12
- **Normal captures with any alert**: 0/10 (0 alerts total)
Since day 63 the IsolationForest is trained on the scenario normal captures,
so for them this is in-sample. `dns_normal.pcap` and `frag_normal.pcap` are held out.

## Attack captures

| Capture | Expected | In training | Detected | Correct label | Alert kinds |
|---|---|---|---|---|---|
| scan.pcap | port_scan | yes | yes | yes | distributed_scan x1, port_scan x2, slow_scan x1 |
| bruteforce.pcap | brute_force | yes | yes | yes | brute_force x1 |
| dos.pcap | dos | yes | yes | yes | dos x4, slowloris x1 |
| decoy.pcap | port_scan | yes | yes | yes | distributed_scan x1, port_scan x72, slow_scan x6 |
| scan_syn_lo.pcap | port_scan | yes | yes | yes | distributed_scan x1, port_scan x1, slow_scan x1 |
| scan_slow_router.pcap | port_scan | yes | yes | yes | distributed_scan x1, port_scan x3, slow_scan x1 |
| scan_connect_router.pcap | port_scan | yes | yes | yes | distributed_scan x1, port_scan x3, slow_scan x1 |
| decoy2_router.pcap | port_scan | yes | yes | yes | distributed_scan x1, port_scan x12, slow_scan x3 |
| udp_scan1.pcap | udp_scan | yes | yes | yes | distributed_scan x1, slow_scan x1, udp_scan x11 |
| udp_scan2.pcap | udp_scan | yes | yes | yes | distributed_scan x1, slow_scan x1, udp_scan x11 |
| syn_flood1.pcap | syn_flood | yes | yes | yes | slowloris x1, syn_flood x4 |
| syn_flood2.pcap | syn_flood | yes | yes | yes | slowloris x1, syn_flood x4 |
| stealth_sX.pcap | stealth_scan | no | yes | yes | distributed_scan x1, slow_scan x1, stealth_scan x2 |
| stealth_sN.pcap | stealth_scan | no | yes | yes | distributed_scan x1, slow_scan x1, stealth_scan x2 |
| stealth_sF.pcap | stealth_scan | no | yes | yes | distributed_scan x1, slow_scan x1, stealth_scan x2 |
| frag_scan.pcap | fragmented_scan | no | yes | yes | fragmented_scan x1 |
| frag_normal.pcap | port_scan | no | yes | yes | distributed_scan x1, port_scan x2, slow_scan x1 |
| slowloris1.pcap | slowloris | no | yes | yes | slowloris x1 |
| slowloris_test.pcap | slowloris | no | yes | yes | slowloris x1 |

## Normal captures (false alerts)

| Capture | Alerts | Alert kinds |
|---|---|---|
| normal.pcap | 0 | - |
| normal_web.pcap | 0 | - |
| normal_stream.pcap | 0 | - |
| normal_mixed.pcap | 0 | - |
| normal_dns1.pcap | 0 | - |
| normal_dns2.pcap | 0 | - |
| dns_div1.pcap | 0 | - |
| dns_div2.pcap | 0 | - |
| dns_div3.pcap | 0 | - |
| dns_normal.pcap | 0 | - |

## Tests

```
78 passed in 130.60s (0:02:10)
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

