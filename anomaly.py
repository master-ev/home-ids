import pandas as pd
from scapy.all import rdpcap
from collections import defaultdict, Counter
from sklearn.ensemble import IsolationForest
from features import get_ips_ports, flow_key, compute_rich_features

def load_flows(filename):
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
        rows.append(feats)
    return pd.DataFrame(rows)
normal = load_flows("normal.pcap")
feature_cols = list(normal.columns)
print(f"Training on {len(normal)} normal flows, {len(feature_cols)} features")
model = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
model.fit(normal[feature_cols])
def test(filename):
    df = load_flows(filename)
    df = df[feature_cols]
    preds = model.predict(df)
    counts = Counter(preds)
    anomalies = counts.get(-1, 0)
    total = len(preds)
    print(f"{filename}: {anomalies}/{total} flagged as anomalies" f"({100*anomalies/total:.0f}%)")
print()
test("normal.pcap")
test("scan.pcap")
test("bruteforce.pcap")