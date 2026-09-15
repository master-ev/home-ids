import joblib
import pandas as pd
from scapy.all import sniff, conf
from collections import defaultdict
from datetime import datetime
from sklearn.ensemble import IsolationForest
from features import get_ips_ports, flow_key, compute_rich_features

conf.use_pcap = True
INTERFACE = "eth1"
WINDOW_SECONDS = 5
saved = joblib.load("my_model.joblib")
classifier = saved["model"]
clf_features = saved["features"]

from scapy.all import rdpcap
def load_normal():
    packets = rdpcap("normal.pcap")
    flows = defaultdict(list)
    for p in packets:
        info = get_ips_ports(p)
        if info: flows[flow_key(info)].append(p)
    rows = []
    for key, pkts in flows.items():
        f = compute_rich_features(pkts)
        f["destination_port"] = get_ips_ports(pkts[0])[3]
        rows.append(f)
    return pd.DataFrame(rows)

normal = load_normal()
anomaly_features = list(normal.columns)
anomaly_model = IsolationForest(contamination=0.15, random_state=42)
anomaly_model.fit(normal[anomaly_features])

print(f"Live IDS running on {INTERFACE}, {WINDOW_SECONDS}s windows\n")
def analyze_window(packets):
    flows = defaultdict(list)
    for p in packets:
        info = get_ips_ports(p)
        if info is not None:
            flows[flow_key(info)].append(p)
    if not flows:
        return
    for key, pkts in flows.items():
        feats = compute_rich_features(pkts)
        feats["destination_port"] = get_ips_ports(pkts[0])[3]
        clf_row = pd.DataFrame([{n: feats.get(n, 0) for n in clf_features}])[clf_features]
        anom_row = pd.DataFrame([{n: feats.get(n, 0) for n in anomaly_features}])[anomaly_features]
        clf_verdict = classifier.predict(clf_row)[0]
        anom_verdict = anomaly_model.predict(anom_row)[0]
        is_attack = (clf_verdict != "normal") or (anom_verdict == -1)
        if is_attack:
            info = get_ips_ports(pkts[0])
            src, dst, sport, dport, proto = info
            reason = clf_verdict if clf_verdict != "normal" else "anomaly"
            now = datetime.now().strftime("%H:%M:%S")
            print(f"[{now}] ALERT ({reason}): {proto} {src}:{sport} -> {dst}:{dport}")
try:
    while True:
        packets = sniff(iface=INTERFACE, timeout=WINDOW_SECONDS, filter="tcp or udp")
        analyze_window(packets)
except KeyboardInterrupt:
    print("\nStopped")