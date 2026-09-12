import joblib
import pandas as pd
from scapy.all import rdpcap
from collections import defaultdict
from features import get_ips_ports, flow_key, compute_rich_features

saved = joblib.load("ids_model_matched.joblib")
model = saved["model"]
expected_features = saved["features"]
print(f"Model expects {len(expected_features)} features:")
print(expected_features)
packets = rdpcap("capture.pcap")
flows = defaultdict(list)
for packet in packets:
    info = get_ips_ports(packet)
    if info is not None:
        flows[flow_key(info)].append(packet)
print(f"\n{len(flows)} flows in my capture\n")
rows = []
flow_info = []
for key, pkts in flows.items():
    feats = compute_rich_features(pkts)
    feats["destination_port"] = get_ips_ports(pkts[0])[3]
    row = {}
    for name in expected_features:
        row[name] = feats.get(name, 0)
    rows.append(row)
    flow_info.append(get_ips_ports(pkts[0]))
X = pd.DataFrame(rows)[expected_features]
predictions = model.predict(X)
for info, pred in zip(flow_info, predictions):
    src, dst, sport, dport, proto = info
    print(f"{proto} {src}:{sport} -> {dst}:{dport} => {pred}")