# Day 35 - Holdout on an unseen capture: every feature set failed

## Results
- check_direction: dos.pcap has 36672 real replies but features counted 0;
  bruteforce.pcap 9996 vs 0. All flows have the same IP on both ends (lo).
  Bug in compute_rich_features: direction decided by IP only.
- Original model on decoy.pcap: 720/720 flows -> dos.
- Random split accuracy: 0.9986 for sets A, B and C (identical).
- Holdout decoy.pcap: 0% correct for A, B and C (all predicted dos).
- Set C top feature: ctx_flows_per_port, so context was used, but not enough.

## Lessons
- A random split cannot tell a model that generalizes from one that does not.
- With one capture per class, the model learns the capture's fingerprint
  (interface, nmap mode, packet size, speed, bugs), not the behavior.
- Values outside the training range (decoy: ~11 flows/window vs 500-1000)
  make trees extrapolate arbitrarily.
- rst_count / ack_count still leak "did the target reply".

## Next (day 36)
Direction fix by (IP, port), 9 new scenario captures, leave-one-capture-out.