import pandas as pd
from scapy.all import rdpcap
from collections import defaultdict
from features import get_ips_ports, flow_key, compute_features

packets = rdpcap("capture.pcap")
flows = defaultdict(list)
for packet in packets:
    info = get_ips_ports(packet)
    if info is not None:
        flows[flow_key(info)].append(packet)

rows = []
for key, pkts in flows.items():
    rows.append(compute_features(pkts))
df = pd.DataFrame(rows)
print(f"{len(df)} flows\n")
print(df)
df.to_csv("flows.csv", index=False)
print("\nSaved flows.csv")
print("\nFlows per destination port:")
print(df["destination_port"].value_counts())
print("\nAverage bytes per flow:", round(df["total_bytes"].mean()))