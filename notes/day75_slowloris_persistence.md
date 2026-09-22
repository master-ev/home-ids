# Day 75 - Slowloris: half-open and short-lived are not "slow"

## Problem (measured since day 71)
Wrong labels in log: 3/20 - slowloris on syn_flood1, syn_flood2 and dos.
Old rule: many connections, few packets each, same port. That matches SYN flood
half-open connections and short HTTP flood connections as well.

## Diagnosis (diagnose_slowloris.py)
<FILL IN per capture: candidates / established / open / persistent>

## Two complementary signatures
1. Established: the initiator must have sent an ACK. A SYN flood never completes
   the handshake (same RFC 793 fact as days 60 and 65).
2. Persistence: Slowloris holds the SAME connections open across windows; floods
   open new ones. Overlap of connection keys between consecutive windows.
Plus: a connection closed (FIN/RST) in the window is not held open.
Threshold SLOWLORIS_MIN_PERSISTENT = <FILL IN>, from the diagnosis.

## Results
Wrong in log 3/20 -> <FILL IN>/20. slowloris1 / slowloris_test still detected.
Soak holdout (381467 real packets): <FILL IN> alerts - long-lived legitimate
connections (streaming, keep-alive) do not trigger it.

## Mutations
- no handshake check: SYN flood replays fail
- no persistence check: dos replay fails
Each flood type is caught by its own signature.

## Leftover
trackers.slowloris_candidates is no longer used by the pipeline (its unit tests
still guard it). Remove in day 76 after the metrics confirm the new logic.