import sys
from collections import Counter, defaultdict
import pandas as pd
from scapy.all import rdpcap, IP, TCP
import live_ids
import trackers
from features import get_ips_ports, flow_key, compute_rich_features
from context import CONTEXT_FEATURES, compute_context
from feature_sets import clean_features
from replay import split_into_windows

TOP_VERDICTS = 3

def payload_stats(packets):
    sizes = []
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            sizes.append(live_ids.tcp_payload_length(pkt))
    if len(sizes) == 0:
        return 0, 0
    return min(sizes), max(sizes)

def diagnose(path):
    packets = rdpcap(path)
    windows = split_into_windows(packets, live_ids.WINDOW_SECONDS)
    verdicts = Counter()
    confidences = []
    tracker_ports = defaultdict(set)
    for window in windows:
        flows = defaultdict(list)
        for p in window:
            info = get_ips_ports(p)
            if info is not None:
                flows[flow_key(info)].append(p)
        if len(flows) == 0:
            continue
        flow_list = list(flows.values())
        context_rows = compute_context(flow_list)
        position = 0
        for key in flows:
            pkts = flows[key]
            feats = compute_rich_features(pkts)
            feats["destination_port"] = get_ips_ports(pkts[0])[3]
            context = context_rows[position]
            for name in CONTEXT_FEATURES:
                feats[name] = context[name]
            position = position + 1
            row = pd.DataFrame([{n: feats.get(n, 0) for n in live_ids.clf_features_v2}])[live_ids.clf_features_v2]
            row = clean_features(row)
            probabilities = live_ids.classifier_v2.predict_proba(row)[0]
            best_index = probabilities.argmax()
            verdict = live_ids.classifier_v2.classes_[best_index]
            verdicts[verdict] = verdicts[verdict] + 1
            confidences.append(float(probabilities[best_index]))
            src, dst, sport, dport, proto = get_ips_ports(pkts[0])
            flags = live_ids.first_tcp_flags(pkts[0])
            if trackers.counts_as_scan_probe(flags):
                tracker_ports[(src, dst)].add(dport)
    smallest, largest = payload_stats(packets)
    best_pair = 0
    for pair in tracker_ports:
        if len(tracker_ports[pair]) > best_pair:
            best_pair = len(tracker_ports[pair])
    average_confidence = 0.0
    if len(confidences) > 0:
        average_confidence = sum(confidences) / len(confidences)
    print(path)
    print(f"  TCP payload bytes: min {smallest}, max {largest}")
    print(f"  Model verdicts: {dict(verdicts.most_common(TOP_VERDICTS))}")
    print(f"  Mean confidence: {average_confidence:.2f}")
    print(f"  Distinct probe ports the trackers see: {best_pair}")
    print()

def main():
    if len(sys.argv) < 2:
        print("Usage: venv/bin/python check_padding.py capture1.pcap [...]")
        return
    live_ids.load_models()
    for path in sys.argv[1:]:
        diagnose(path)

if __name__ == "__main__":
    main()