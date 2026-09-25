import sys
from collections import defaultdict
import pandas as pd
from features import get_ips_ports, flow_key, compute_rich_features
from feature_sets import clean_features
from scapy.all import rdpcap
import live_ids

def flows_of(path):
    packets = rdpcap(path)
    flows = defaultdict(list)
    for pkt in packets:
        info = get_ips_ports(pkt)
        if info is not None:
            flows[flow_key(info)].append(pkt)
    return flows

def feature_frame(flows):
    rows = []
    for key, pkts in flows.items():
        feats = compute_rich_features(pkts)
        feats["destination_port"] = get_ips_ports(pkts[0])[3]
        row = {}
        for name in live_ids.clf_features_v2:
            row[name] = feats.get(name, 0)
        rows.append(row)
    frame = pd.DataFrame(rows, columns=live_ids.clf_features_v2)
    frame = clean_features(frame)
    return frame

def main():
    if len(sys.argv) < 3:
        print("usage: venv/bin/python diagnose_payload_distinct.py flood.pcap normal.pcap")
        return
    live_ids.load_models()
    flood_frame = feature_frame(flows_of(sys.argv[1]))
    normal_frame = feature_frame(flows_of(sys.argv[2]))
    print("flood flows:  " + str(len(flood_frame)))
    print("normal flows: " + str(len(normal_frame)))
    print("")
    print("feature                     flood_mean   normal_mean   differ")
    seen = set()
    for name in live_ids.clf_features_v2:
        if name in seen:
            continue
        seen.add(name)
        flood_column = flood_frame[name]
        normal_column = normal_frame[name]
        if isinstance(flood_column, pd.DataFrame):
            flood_column = flood_column.iloc[:, 0]
            normal_column = normal_column.iloc[:, 0]
        flood_mean = float(flood_column.mean())
        normal_mean = float(normal_column.mean())
        gap = abs(flood_mean - normal_mean)
        scale = max(abs(flood_mean), abs(normal_mean), 1.0)
        relative = gap / scale
        if relative > 0.5:
            marker = "YES"
        else:
            marker = ""
        print(name.ljust(28) + str(round(flood_mean, 2)).rjust(11) + str(round(normal_mean, 2)).rjust(14) + marker.rjust(9))

if __name__ == "__main__":
    main()