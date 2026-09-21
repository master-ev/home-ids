# Day 68 - Notifications grouped by family (MITRE ATT&CK tactics)

## Problem
One simple scan still gave 2-3 notices: port_scan + slow_scan (+ distributed_scan).
Redundant detectors are good for detection, noise for the human.

## Design
- KIND_FAMILY: recon, evasion, access, flood, anomaly, unclassified
  (Reconnaissance, Defense Evasion, Credential Access, Impact)
- cooldown key: (source, destination, FAMILY) - escalation to a new family always passes
- FAMILY_COVERS = {evasion: [recon]}: asymmetric - a stealth scan IS recon,
  but recon then stealth is new information and is notified
- fail-safe: an unmapped kind is its own family (one notice too many, never too few)
- next notice lists silent detectors: "+3 similar: port_scan x2, slow_scan x1"

## Safety property, updated
Day 66: every (source, destination, kind) notified once. Now: every logged alert is
COVERED by a notice of its family or a covering family, for its own
(source, destination). No source is ever hidden (decoy test).

## Results
<FILL IN: attack alerts logged / notified; decoy 13 -> ?; dos 2 -> ?>
Logged / detected / correct label / kinds unchanged. Tests: 93 -> 100.

## Mutations
- everything one family: escalation tests fail
- FAMILY_COVERS emptied: recon-after-evasion test fails

## Limitations
- inside a family the FIRST detector wins the console line (scan.pcap shows
  SLOW PORT SCAN, the "1000 ports" detail stays in the log)
- distributed_scan has source "multiple": separate key, separate notice (on purpose)

## Results
- Attack alerts: 173 logged -> 38 notified (day 66: 60). Kinds unchanged.
- decoy 13 -> 7, dos 2 -> 1, syn_flood 2 -> 1, stealth 3 -> 2, scans 3 -> 2
- All rows exactly as predicted before running.

## Found: first detector wins = information loss
udp_scan1/2: the console shows only SLOW PORT SCAN + DISTRIBUTED SCAN;
the specific label UDP SCAN is never shown (logged only). scan.pcap: PORT SCAN
(1000 ports) hidden behind SLOW PORT SCAN (15 ports). The generic tracker
fires first in the window and hides the most specific label.