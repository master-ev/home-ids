import sys
from collections import Counter, defaultdict
import live_ids
import pandas as pd
from features import get_ips_ports, flow_key, compute_rich_features
from feature_sets import clean_features
from scapy.all import rdpcap

ATTACKER = "192.168.1.236"
ROUTER = "192.168.1.1"

def group_flows(packets):
    flows = defaultdict(list)
    for pkt in packets:
        info = get_ips_ports(pkt)
        if info is not None:
            flows[flow_key(info)].append(pkt)
    return flows

def main():
    if len(sys.argv) < 2:
        print("usage: venv/bin/python diagnose_payload_flood.py capture.pcap")
        return
    live_ids.load_models()
    packets = rdpcap(sys.argv[1])
    flows = group_flows(packets)
    print("total packets: " + str(len(packets)))
    print("total flows:   " + str(len(flows)))
    from_attacker = 0
    verdict_counts = Counter()
    confidence_sum = 0.0
    confidence_n = 0
    for key, pkts in flows.items():
        info = get_ips_ports(pkts[0])
        src = info[0]
        dst = info[1]
        if src != ATTACKER or dst != ROUTER:
            continue
        from_attacker = from_attacker + 1
        feats = compute_rich_features(pkts)
        feats["destination_port"] = info[3]
        row = pd.DataFrame([{n: feats.get(n, 0) for n in live_ids.clf_features_v2}])[live_ids.clf_features_v2]
        row = clean_features(row)
        probabilities = live_ids.classifier_v2.predict_proba(row)[0]
        best_index = probabilities.argmax()
        verdict = live_ids.classifier_v2.classes_[best_index]
        confidence = float(probabilities[best_index])
        verdict_counts[verdict] = verdict_counts[verdict] + 1
        confidence_sum = confidence_sum + confidence
        confidence_n = confidence_n + 1
    print("")
    print("flows attacker -> router: " + str(from_attacker))
    print("verdicts on those flows:")
    for verdict in sorted(verdict_counts.keys()):
        print("  " + verdict.ljust(15) + str(verdict_counts[verdict]))
    if confidence_n > 0:
        mean_conf = confidence_sum / confidence_n
        print("mean confidence: " + str(round(mean_conf, 3)))
    for key, pkts in flows.items():
        info = get_ips_ports(pkts[0])
        if info[0] == ATTACKER and info[1] == ROUTER:
            feats = compute_rich_features(pkts)
            print("")
            print("sample flood flow, packets=" + str(len(pkts)))
            print("  packet_count: " + str(feats.get("packet_count", "?")))
            print("  total_bytes:  " + str(feats.get("total_bytes", "?")))
            print("  mean_pkt_size:" + str(feats.get("mean_pkt_size", "?")))
            break

if __name__ == "__main__":
    main()