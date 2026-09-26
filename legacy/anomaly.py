import pandas as pd
from scapy.all import rdpcap
from collections import defaultdict
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
scan = load_flows("scan.pcap")[feature_cols]
brute = load_flows("bruteforce.pcap")[feature_cols]
normal_test = normal[feature_cols]
print(f"{'contamination':>15} {'normal FP' :>12} {'scan recall':>12} {'brute recall':>13}")
for cont in [0.01, 0.05, 0.1, 0.2, 0.3]:
    model = IsolationForest(contamination=cont, random_state=42, n_estimators=100)
    model.fit(normal[feature_cols])
    def anomaly_rate(df):
        preds = model.predict(df)
        return sum(1 for p in preds if p == -1) / len(preds)
    fp = anomaly_rate(normal_test)
    scan_r = anomaly_rate(scan)
    brute_r = anomaly_rate(brute)
    print(f"{cont:>15} {fp:>11.0%} {scan_r:>11.0%} {brute_r:>12.0%}")

















# def test(filename):
#     df = load_flows(filename)
#     df = df[feature_cols]
#     preds = model.predict(df)
#     counts = Counter(preds)
#     anomalies = counts.get(-1, 0)
#     total = len(preds)
#     print(f"{filename}: {anomalies}/{total} flagged as anomalies" f"({100*anomalies/total:.0f}%)")
# print()
# test("normal.pcap")
# test("scan.pcap")
# test("bruteforce.pcap")