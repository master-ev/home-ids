import pandas as pd
from scapy.all import rdpcap
from collections import defaultdict
from features import get_ips_ports, flow_key, compute_rich_features

def flows_from_pcap(filename, label):
    packets = rdpcap(filename)
    flows = defaultdict(list)
    for p in packets:
        info = get_ips_ports(p)
        if info is not None:
            flows[flow_key(info)].append(p)
    rows = []
    for key, pkts in flows.items():
        feats = compute_rich_features(pkts)
        feats["destination_port"] = get_ips_ports(pkts[0])[3]
        feats["label"] = label
        rows.append(feats)
    return rows

normal_rows = flows_from_pcap("normal.pcap", "normal")
scan_rows = flows_from_pcap("scan.pcap", "scan")
brute_rows = flows_from_pcap("bruteforce.pcap", "bruteforce")
print(f"Normal flows: {len(normal_rows)}")
print(f"Scan flows: {len(scan_rows)}")
print(f"Brute-force flows: {len(brute_rows)}")
df = pd.DataFrame(normal_rows + scan_rows + brute_rows)
df.to_csv("my_dataset.csv", index=False)
print(f"\nSaved my_dataset.csv with {len(df)} labeled flows")
print("\nLabel distribution:")
print(df["label"].value_counts())