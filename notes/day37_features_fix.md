# Day 37-38 - Direction bug fix and locking the model on correct data

## The bug the test caught
test_features.py (real-capture based) failed: total_fwd_packets = 0 for
scan.pcap AND dos.pcap. A scan's first packet is always forward, so 0 was
impossible. Cause: initiator_port read index 3 (destination port) instead
of index 2 (source port), so every packet fell to backward.
Fix: initiator_port = first_info[2]; direction decided by (IP, port).

## lo is uncapturable in this WSL
tcpdump on lo returned 0 packets (scapy did too). capture_run.py proved
capture+traffic were simultaneous, so it is not a timing issue - lo simply
does not deliver to libpcap here. DoS and brute-force therefore stay
single-capture (dos.pcap, bruteforce.pcap) and cannot be LOCO-validated.
Documented limitation, like the localhost-live limitation.

## After the fix
- Rebuilt my_dataset_v2.csv with correct forward features.
- Re-ran LOCO to revalidate: a feature change invalidates old results.
- Chosen set: C (no backward/port features + context). C and D tie on the
  numbers; C keeps rst/ack, which after the direction fix distinguish
  closed-port scans (RST) from filtered-port scans (no reply).
- Model locked: my_model_v2.joblib (set C).

## normal fixed (day 37)
WSL-generated HTTPS traffic (normal_web/stream/mixed) raised normal from
11.4% to ~88% held out. Real, varied, reproducible.