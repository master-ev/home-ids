import joblib
import pandas as pd
import json
from scapy.all import sniff, conf
from collections import Counter, defaultdict
from datetime import datetime
import time
from sklearn.ensemble import IsolationForest
from features import get_ips_ports, flow_key, compute_rich_features
from context import CONTEXT_FEATURES, compute_context
from feature_sets import clean_features
from net_iface import active_interface, ROUTER_IP

USE_V2 = True
V2_MODEL_PATH = "my_model_v2.joblib"
port_history = defaultdict(list)
SLOW_SCAN_WINDOW = 300 # seconds
SLOW_SCAN_THRESHOLD = 15
slow_scan_alerted = set()
dest_history = defaultdict(list)
DEST_SCAN_THRESHOLD = 20
SCAN_MIN_PORTS = 10
MIN_ATTACK_FLOWS = 10
FEW_PORTS_MAX = 3
SUSPICIOUS_MIN_FLOWS = 5
dest_scan_alerted = set()

conf.use_pcap = True
INTERFACE = active_interface(ROUTER_IP)
print(f"Auto-detected interface: {INTERFACE}")
WINDOW_SECONDS = 5
ALERT_LOG = "alerts.jsonl"
saved = joblib.load("my_model.joblib")
if USE_V2:
    saved_v2 = joblib.load(V2_MODEL_PATH)
    classifier_v2 = saved_v2["model"]
    clf_features_v2 = saved_v2["features"]
    print(f"Using v2 model (set {saved_v2.get('feature_set', '?')}, " f"{len(clf_features_v2)} features)")
classifier = saved["model"]
clf_features = saved["features"]

def log_alert(alert):
    with open(ALERT_LOG, "a") as f:
        f.write(json.dumps(alert) + "\n")

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

def check_slow_scan(src, dst, dport):
    now = time.time()
    key = (src, dst)
    port_history[key].append((dport, now))
    port_history[key] = [(p, t) for (p, t) in port_history[key] if now - t < SLOW_SCAN_WINDOW]
    distinct_ports = len(set(p for (p, t) in port_history[key]))
    if distinct_ports >= SLOW_SCAN_THRESHOLD and key not in slow_scan_alerted:
        slow_scan_alerted.add(key)
        return distinct_ports
    return None

def check_dest_scan(dst, dport):
    now = time.time()
    dest_history[dst].append((dport, now))
    dest_history[dst] = [(p, t) for (p, t) in dest_history[dst] if now - t < SLOW_SCAN_WINDOW]
    distinct_ports = len(set(p for (p, t) in dest_history[dst]))
    if distinct_ports >= DEST_SCAN_THRESHOLD and dst not in dest_scan_alerted:
        dest_scan_alerted.add(dst)
        return distinct_ports
    return None

def analyze_window(packets):
    flows = defaultdict(list)
    for p in packets:
        info = get_ips_ports(p)
        if info is not None:
            flows[flow_key(info)].append(p)
    if not flows:
        return
    campaigns = defaultdict(lambda: {"ports": set(), "count": 0, "verdicts": Counter()})
    flow_list = list(flows.values())
    context_rows = compute_context(flow_list)
    position = 0
    for key, pkts in flows.items():
        feats = compute_rich_features(pkts)
        feats["destination_port"] = get_ips_ports(pkts[0])[3]
        context = context_rows[position]
        for name in CONTEXT_FEATURES:
            feats[name] = context[name]
        position = position + 1
        if USE_V2:
            v2_row = pd.DataFrame([{n: feats.get(n, 0) for n in clf_features_v2}])[clf_features_v2]
            v2_row = clean_features(v2_row)
            clf_verdict = classifier_v2.predict(v2_row)[0]
        else:
            clf_row = pd.DataFrame([{n: feats.get(n, 0) for n in clf_features}])[clf_features]
            clf_verdict = classifier.predict(clf_row)[0]
        anom_row = pd.DataFrame([{n: feats.get(n, 0) for n in anomaly_features}])[anomaly_features]
        anom_verdict = anomaly_model.predict(anom_row)[0]
        is_attack = (clf_verdict != "normal") or (anom_verdict == -1)
        src, dst, sport, dport, proto = get_ips_ports(pkts[0])
        slow = check_slow_scan(src, dst, dport)
        if slow is not None:
            now_str = datetime.now().strftime("%H:%M:%S")
            print(f"[{now_str}] ALERT: SLOW PORT SCAN ({slow} ports over time) {src} -> {dst}")
            log_alert({"timestamp": datetime.now().isoformat(), "kind": "slow_scan", "description": f"SLOW PORT SCAN ({slow} ports over time)", "source": src, "destination": dst, "num_flows": slow, "num_ports": slow, "model_verdict": "slow_scan",})
        dscan = check_dest_scan(dst, dport)
        if dscan is not None:
            now_str = datetime.now().strftime("%H:%M:%S")
            print(f"[{now_str}] ALERT: DISTRIBUTED SCAN ({dscan} ports on target, multiple sources) -> {dst}")
            log_alert({"timestamp": datetime.now().isoformat(), "kind": "distributed_scan", "description": f"DISTRIBUTED SCAN ({dscan} ports on target)", "source": "multiple", "destination": dst, "num_flows": dscan, "num_ports": dscan, "model_verdict": "distributed_scan"})
        if is_attack:
            pair = (src, dst)
            campaigns[pair]["ports"].add(dport)
            campaigns[pair]["count"] += 1
            reason = clf_verdict if clf_verdict != "normal" else "anomaly"
            campaigns[pair]["verdicts"][reason] += 1
    now = datetime.now().strftime("%H:%M:%S")
    for (src, dst), data in campaigns.items():
        num_ports = len(data["ports"])
        num_flows = data["count"]
        main_verdict = data["verdicts"].most_common(1)[0][0]
        if num_ports >= SCAN_MIN_PORTS:
            kind = "port_scan"
            desc = f"PORT SCAN({num_ports} ports)"
        elif main_verdict == "dos" and num_flows > MIN_ATTACK_FLOWS and num_ports <= FEW_PORTS_MAX:
            kind = "dos"
            desc = f"DoS FLOOD ({num_flows} flows)"
        elif num_flows > MIN_ATTACK_FLOWS and num_ports <= FEW_PORTS_MAX:
            kind = "brute_force"
            desc = f"BRUTE FORCE ({num_flows} attempts)"
        elif num_flows >= SUSPICIOUS_MIN_FLOWS:
            kind = "suspicious"
            desc = f"{num_flows} suspicious flows"
        else:
            continue
        timestamp = datetime.now().isoformat()
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ALERT: {desc} {src} -> {dst} (model: {main_verdict})")
        log_alert({"timestamp": timestamp, "kind": kind, "description": desc, "source": src, "destination": dst, "num_flows": num_flows, "num_ports": num_ports, "model_verdict": main_verdict,})
try:
    while True:
        packets = sniff(iface=INTERFACE, timeout=WINDOW_SECONDS, filter="tcp or udp")
        analyze_window(packets)
except KeyboardInterrupt:
    print("\nStopped")