import joblib
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
    rows, infos  = [], []
    for key, pkts in flows.items():
        feats = compute_rich_features(pkts)
        feats["destination_port"] = get_ips_ports(pkts[0])[3]
        rows.append(feats)
        infos.append(get_ips_ports(pkts[0]))
    return pd.DataFrame(rows), infos

saved = joblib.load("my_model.joblib")
classifier = saved["model"]
clf_features = saved["features"]
normal, _ = load_flows("normal.pcap")
anomaly_features = list(normal.columns)
anomaly_model = IsolationForest(contamination=0.15, random_state=42, n_estimators=100)
anomaly_model.fit(normal[anomaly_features])

def detect(filename):
    df, infos = load_flows(filename)
    X_clf = df[clf_features]
    clf_pred = classifier.predict(X_clf)
    X_anom = df[anomaly_features]
    anom_pred = anomaly_model.predict(X_anom)
    alerts = 0
    for clf, anom in zip(clf_pred, anom_pred):
        is_attack = (clf != "normal") or (anom == -1)
        if is_attack:
            alerts += 1
    print(f"{filename}: {alerts}/{len(df)} flows flagged as suspicious")
    print(f"    classifier verdicts: {Counter(clf_pred)}")
print()
detect("normal.pcap")
detect("scan.pcap")
detect("bruteforce.pcap")