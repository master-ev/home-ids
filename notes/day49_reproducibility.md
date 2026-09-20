# Day 49 - LOCO reproducibility and the is_tcp fix

## Reproducibility: confirmed OK
Two consecutive LOCO runs are identical; rebuild does not change results.
The day-47 vs day-48 difference was NOT non-determinism - it was that features
had changed (ctx_reply_rate added day 47, ICMP parsing added day 48). Rule
re-confirmed: any features change invalidates old results; re-run LOCO.

## The real problem: protocol was implicit
After adding ctx_reply_rate, set D confused decoy (TCP SYN scan) with udp_scan:
both have reply_rate 0 and similar context volume. The distinguishing signal
(TCP vs UDP) lived only implicitly in syn_count, which the forest ignored
(MDI importance 0.0057). Adding reply_rate pushed the forest further onto
context features, so decoy dropped to 0% in LOCO.

## Fix: explicit is_tcp feature
is_tcp = 1 for TCP, 0 otherwise. Added in three places (the feature pipeline):
compute_rich_features (calc), build_dataset_v2 (copy into row), feature_sets
(include in every set). Result: decoy back to 100%, normal_dns1 to 97.5%.

## Lesson on feature importance
is_tcp global MDI importance is still tiny (0.0057) yet it fixed decoy from
0% to 100%. A low global importance can still be decisive for a narrow case
(decoy vs udp_scan). Low importance != useless.

## Lesson on the pipeline
A new feature must be added in THREE places: compute_rich_features, the copy
loop in build_dataset_v2, and feature_sets. Missing the copy step gave a silent
KeyError only at LOCO time.

## Known regression (deferred to a dedicated day)
The retrained set-D model classifies an UNSEEN DNS capture (dns_normal.pcap,
not in training) at only ~67% normal (26/39; 8 scan, 5 dos), down from 100%
at day 47. LOCO on the in-dataset DNS captures shows 97.5%, so this is a
data-coverage gap, not a reproducibility problem: DNS is varied (to router, to
public resolver, different queries) and only 2 DNS captures are in training.
is_tcp groups DNS with udp_scan (both is_tcp=0); reply_rate should separate
them but on unseen DNS the separation is weaker. Fix on a dedicated day:
capture more diverse normal DNS/UDP traffic. Same lesson as day 37/47:
new normal traffic types need enough diverse examples.