import joblib
import pandas as pd
import json
from scapy.all import sniff, conf, IP
from collections import Counter, defaultdict
from datetime import datetime
import time
from sklearn.ensemble import IsolationForest
from features import get_ips_ports, flow_key, compute_rich_features
from context import CONTEXT_FEATURES, compute_context
from feature_sets import clean_features
from net_iface import active_interface, ROUTER_IP

FRAGMENT_FLOOD_THRESHOLD = 30 
frag_alerted = set()
MODEL_ALERT_MIN_CONFIDENCE = 0.70
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
ICMP_FLOOD_THRESHOLD = 100
ICMP_PROTO = "ICMP"
SLOWLORIS_MIN_CONNECTIONS = 20
SLOWLORIS_MAX_PKTS_PER_CONN = 12
SLOWLORIS_MIN_WINDOWS = 3
slowloris_windows = defaultdict(int)
slowloris_alerted = set()

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

def average_confidence(values):
    if len(values) == 0:
        return None
    total = 0.0
    index = 0
    while index < len(values):
        total = total + values[index]
        index = index + 1
    return round(total / len(values), 3)

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
    frag_counts = {}
    for p in packets:
        if IP in p:
            more_fragments = int(p[IP].flags) & 1
            has_offset = p[IP].frag != 0
            if more_fragments or has_offset:
                pair = (p[IP].src, p[IP].dst)
                if pair not in frag_counts:
                    frag_counts[pair] = 0
                frag_counts[pair] = frag_counts[pair] + 1   
    icmp_counts = {}
    for p in packets:
        info = get_ips_ports(p)
        if info is not None and info[4] == ICMP_PROTO:
            pair = (info[0], info[1])
            if pair not in icmp_counts:
                icmp_counts[pair] = 0
            icmp_counts[pair] = icmp_counts[pair] + 1
    slowloris_counts = {}
    for key, pkts in flows.items():
        info = get_ips_ports(pkts[0])
        if info is None:
            continue
        src, dst, sport, dport, proto = info
        if proto != "TCP":
            continue
        server_port = min(sport, dport)
        if len(pkts) <= SLOWLORIS_MAX_PKTS_PER_CONN:
            host_a = min(src, dst)
            host_b = max(src, dst)
            triple = (host_a, host_b, server_port)
            if triple not in slowloris_counts:
                slowloris_counts[triple] = 0
            slowloris_counts[triple] = slowloris_counts[triple] + 1
            if triple not in slowloris_counts:
                slowloris_counts[triple] = 0
            slowloris_counts[triple] = slowloris_counts[triple] + 1
    flow_list = list(flows.values())
    context_rows = compute_context(flow_list)
    campaigns = defaultdict(lambda: {"ports": set(), "count": 0, "verdicts": Counter(), "confidences": []})
    position = 0
    for key, pkts in flows.items():
        first_info = get_ips_ports(pkts[0])
        if first_info is not None and first_info[4] == ICMP_PROTO:
            position = position + 1
            continue
        feats = compute_rich_features(pkts)
        feats["destination_port"] = get_ips_ports(pkts[0])[3]
        context = context_rows[position]
        for name in CONTEXT_FEATURES:
            feats[name] = context[name]
        position = position + 1
        if USE_V2:
            v2_row = pd.DataFrame([{n: feats.get(n, 0) for n in clf_features_v2}])[clf_features_v2]
            v2_row = clean_features(v2_row)
            probabilities = classifier_v2.predict_proba(v2_row)[0]
            best_index = probabilities.argmax()
            clf_verdict = classifier_v2.classes_[best_index]
            confidence = float(probabilities[best_index])
        else:
            clf_row = pd.DataFrame([{n: feats.get(n, 0) for n in clf_features}])[clf_features]
            probabilities = classifier.predict_proba(clf_row)[0]
            best_index = probabilities.argmax()
            clf_verdict = classifier.classes_[best_index]
            confidence = float(probabilities[best_index])
        anom_row = pd.DataFrame([{n: feats.get(n, 0) for n in anomaly_features}])[anomaly_features]
        anom_verdict = anomaly_model.predict(anom_row)[0]
        is_attack = (clf_verdict != "normal") or (anom_verdict == -1)
        src, dst, sport, dport, proto = get_ips_ports(pkts[0])
        slow = check_slow_scan(src, dst, dport)
        if slow is not None:
            now_str = datetime.now().strftime("%H:%M:%S")
            print(f"[{now_str}] ALERT: SLOW PORT SCAN ({slow} ports over time) {src} -> {dst}")
            log_alert({"timestamp": datetime.now().isoformat(), "kind": "slow_scan", "description": f"SLOW PORT SCAN ({slow} ports over time)", "source": src, "destination": dst, "num_flows": slow, "num_ports": slow, "model_verdict": "slow_scan", "confidence": None})
        dscan = check_dest_scan(dst, dport)
        if dscan is not None:
            now_str = datetime.now().strftime("%H:%M:%S")
            print(f"[{now_str}] ALERT: DISTRIBUTED SCAN ({dscan} ports on target, multiple sources) -> {dst}")
            log_alert({"timestamp": datetime.now().isoformat(), "kind": "distributed_scan", "description": f"DISTRIBUTED SCAN ({dscan} ports on target)", "source": "multiple", "destination": dst, "num_flows": dscan, "num_ports": dscan, "model_verdict": "distributed_scan", "confidence": None})
        if is_attack:
            pair = (src, dst)
            campaigns[pair]["ports"].add(dport)
            campaigns[pair]["count"] += 1
            reason = clf_verdict if clf_verdict != "normal" else "anomaly"
            campaigns[pair]["verdicts"][reason] += 1
            if clf_verdict != "normal":
                campaigns[pair]["confidences"].append(confidence)
    for (src, dst), data in campaigns.items():
        num_ports = len(data["ports"])
        num_flows = data["count"]
        main_verdict = data["verdicts"].most_common(1)[0][0]
        if main_verdict == "udp_scan" and num_flows >= SUSPICIOUS_MIN_FLOWS:
            kind = "udp_scan"
            desc = f"UDP SCAN({num_ports} ports)"
        elif main_verdict == "syn_flood" and num_flows > MIN_ATTACK_FLOWS and num_ports <= FEW_PORTS_MAX:
            kind = "syn_flood"
            desc = f"SYN FLOOD ({num_flows} half-open)"
        elif num_ports >= SCAN_MIN_PORTS:
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
        confidence = average_confidence(data["confidences"])
        if confidence is not None and confidence < MODEL_ALERT_MIN_CONFIDENCE:
            continue
        confidence_text = ""
        if confidence is not None:
            confidence_text = f" conf={confidence:.2f}"
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ALERT: {desc} " f"{src} -> {dst} (model: {main_verdict}{confidence_text})")
        log_alert({"timestamp": timestamp, "kind": kind, "description": desc, "source": src, "destination": dst, "num_flows": num_flows, "num_ports": num_ports, "model_verdict": main_verdict, "confidence": confidence})
    for pair, count in icmp_counts.items():
        src, dst = pair
        if count >= ICMP_FLOOD_THRESHOLD:
            now_str = datetime.now().strftime("%H:%M:%S")
            timestamp = datetime.now().isoformat()
            desc = f"ICMP FLOOD ({count} packets)"
            print(f"[{now_str}] ALERT: {desc} {src} -> {dst}")
            log_alert({"timestamp": timestamp, "kind": "icmp_flood", "description": desc, "source": src, "destination": dst, "num_flows": count, "num_ports": 0, "model_verdict": "icmp_flood", "confidence": None})
    for pair, count in frag_counts.items():
        src, dst = pair
        if count >= FRAGMENT_FLOOD_THRESHOLD and pair not in frag_alerted:
            frag_alerted.add(pair)
            now_str = datetime.now().strftime("%H:%M:%S")
            timestamp = datetime.now().isoformat()
            desc = f"FRAGMENTED SCAN ({count} fragments - evasion attempt)"
            print(f"[{now_str}] ALERT: {desc} {src} -> {dst}")
            log_alert({"timestamp": timestamp, "kind": "fragmented_scan", "description": desc, "source": src, "destination": dst, "num_flows": count, "num_ports": 0, "model_verdict": "fragmented_scan", "confidence": None})
    for triple, count in slowloris_counts.items():
        host_a, host_b, server_port = triple
        if count >= SLOWLORIS_MIN_CONNECTIONS:
            slowloris_windows[triple] = slowloris_windows[triple] + 1
            if (slowloris_windows[triple] >= SLOWLORIS_MIN_WINDOWS and triple not in slowloris_alerted):
                slowloris_alerted.add(triple)
                now_str = datetime.now().strftime("%H:%M:%S")
                timestamp = datetime.now().isoformat()
                desc = f"SLOWLORIS ({count} slow connections on port {server_port})"
                print(f"[{now_str}] ALERT: {desc} {host_a} <-> {host_b}")
                log_alert({"timestamp": timestamp, "kind": "slowloris", "description": desc, "source": host_a, "destination": host_b, "num_flows": count, "num_ports": 1, "model_verdict": "slowloris", "confidence": None})
        else:
            slowloris_windows[triple] = 0

def run_live():
    print(f"Live IDS running on {INTERFACE}, {WINDOW_SECONDS}s windows\n")
    try:
        while True:
            packets = sniff(iface=INTERFACE, timeout=WINDOW_SECONDS, filter="tcp or udp or icmp")
            analyze_window(packets)
    except KeyboardInterrupt:
        print("\nStopped")

if __name__ == "__main__":
    run_live()