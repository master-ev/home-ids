# Day 64 - Verdict-aware campaign labels

## Diagnosis (diagnose_campaigns.py)
- dos.pcap: verdict=dos, flows/port = <FILL IN>, ephemeral ports = <FILL IN>
- decoy.pcap: verdict=scan, ports per window = <FILL IN>, flows/port = <FILL IN>

## Fix
choose_campaign_label: specific rules (verdict AND shape agree) before
generic shape-only rules.
- dos: verdict dos + (few ports OR >= 5 flows per port)
- scan: verdict scan + <= 2 flows per port, even under SCAN_MIN_PORTS
Flows-per-port replaces absolute port count as the flood/scan signal:
it survives ephemeral-port inflation.

## Guard kept
A scan-shaped campaign is never labelled dos, even if the model says so
(the project's founding bug). Test: test_dos_verdict_with_scan_shape_is_not_dos,
validated by mutation (trusting the verdict blindly makes it fail).

## Results
metrics.md in-training attacks: 10/12 -> <FILL IN>/12 correctly labelled.

## Not fixed
- decoy.pcap still produces ~72 alerts (correct label, too many).
- dos.pcap triggers slow_scan / distributed_scan trackers (inflated ports on
  a same-IP capture).
- No replay test for dos.pcap (2 min); covered by unit test + metrics.

## Mutation
- `if few_ports or looks_like_flood` -> `if True` (trust dos verdict blindly):
  test_dos_verdict_with_scan_shape_is_not_dos FAILS. Restored -> green.
  The founding bug (scan labelled DoS) is now guarded by a test.