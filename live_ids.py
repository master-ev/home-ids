import joblib
import pandas as pd
import json
import trackers
import os
import sys
from scapy.all import sniff, conf, IP, rdpcap, TCP
from collections import Counter, defaultdict
from datetime import datetime
import time
from sklearn.ensemble import IsolationForest
from features import get_ips_ports, flow_key, compute_rich_features
from context import CONTEXT_FEATURES, compute_context
from feature_sets import clean_features
from net_iface import active_interface, ROUTER_IP
from trackers import detect_stealth_scans
from scenarios import CAPTURES

def require_file(path, hint):
    if not os.path.exists(path):
        print(f"[!] Missing required file: {path}")
        print(f"    {hint}")
        print("    Run 'venv/bin/python setup_check.py' for the full checklist.")
        sys.exit(1)
FRAGMENT_FLOOD_THRESHOLD = 30
frag_alerted = set()
MODEL_ALERT_MIN_CONFIDENCE = 0.70
USE_V2 = True
V2_MODEL_PATH = "my_model_v2.joblib"
port_history = defaultdict(list)
SLOW_SCAN_WINDOW = 300
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
WINDOW_SECONDS = 5
ALERT_LOG = "alerts.jsonl"
NORMAL_LABEL = "normal"
ANOMALY_VERDICT = "anomaly"
SCAN_VERDICT = "scan"
DOS_VERDICT = "dos"
FLOOD_MIN_FLOWS_PER_PORT = 5
SCAN_MAX_FLOWS_PER_PORT = 3
ANOMALY_CONTAMINATION = 0.05
ANOMALY_RANDOM_SEED = 42
ALERT_COOLDOWN_SECONDS = 60
last_notified_time = {}
suppressed_counts = defaultdict(int)
classifier = None
clf_features = None
classifier_v2 = None
clf_features_v2 = None
anomaly_model = None
anomaly_features = None
INTERFACE = None

def extract_tcp_info(packets):
    tcp_packets = []
    for pkt in packets:
        has_ip = IP in pkt
        has_tcp = TCP in pkt
        if not (has_ip and has_tcp):
            continue
        src = pkt[IP].src
        dst = pkt[IP].dst
        dport = pkt[TCP].dport
        flags = int(pkt[TCP].flags)
        tcp_packets.append((src, dst, dport, flags))
    return tcp_packets

def first_tcp_flags(pkt):
    if TCP in pkt:
        return int(pkt[TCP].flags)
    return None

def normal_capture_paths():
    paths = []
    for capture_name, label in CAPTURES:
        if label != NORMAL_LABEL:
            continue
        if not os.path.exists(capture_name):
            print(f"[!] Normal capture missing, skipped for anomaly training: {capture_name}")
            continue
        paths.append(capture_name)
    return paths

def load_normal(paths):
    rows = []
    for path in paths:
        packets = rdpcap(path)
        flows = defaultdict(list)
        for p in packets:
            info = get_ips_ports(p)
            if info:
                flows[flow_key(info)].append(p)
        for key, pkts in flows.items():
            f = compute_rich_features(pkts)
            f["destination_port"] = get_ips_ports(pkts[0])[3]
            rows.append(f)
    frame = pd.DataFrame(rows)
    frame = frame.fillna(0)
    return frame

def load_models():
    global classifier, clf_features, classifier_v2, clf_features_v2
    global anomaly_model, anomaly_features
    require_file("my_model.joblib", "The base model. Build with build_my_dataset.py + train_mine.py.")
    saved = joblib.load("my_model.joblib")
    classifier = saved["model"]
    clf_features = saved["features"]
    if USE_V2:
        require_file(V2_MODEL_PATH, "The v2 model. Build with build_dataset_v2.py + train_v2.py D.")
        saved_v2 = joblib.load(V2_MODEL_PATH)
        classifier_v2 = saved_v2["model"]
        clf_features_v2 = saved_v2["features"]
        print(f"Using v2 model (set {saved_v2.get('feature_set', '?')}, " f"{len(clf_features_v2)} features)")
    normal_paths = normal_capture_paths()
    if len(normal_paths) == 0:
        print("[!] No normal captures found for the anomaly model.")
        print("    Check the 'normal' entries in scenarios.py.")
        sys.exit(1)
    normal = load_normal(normal_paths)
    anomaly_features = list(normal.columns)
    anomaly_model = IsolationForest(contamination=ANOMALY_CONTAMINATION, random_state=ANOMALY_RANDOM_SEED)
    anomaly_model.fit(normal[anomaly_features])
    print(f"Anomaly model: {len(normal_paths)} normal captures, {len(normal)} flows, " f"contamination={ANOMALY_CONTAMINATION}")

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

def cooldown_allows(last_time, now, cooldown_seconds):
    if last_time is None:
        return True
    elapsed = now - last_time
    if elapsed >= cooldown_seconds:
        return True
    return False

def emit_alert(alert, console_text, window_time):
    key = (alert["source"], alert["destination"], alert["kind"])
    last_time = last_notified_time.get(key)
    notify = cooldown_allows(last_time, window_time, ALERT_COOLDOWN_SECONDS)
    if notify:
        repeats = suppressed_counts[key]
        suppressed_counts[key] = 0
        last_notified_time[key] = window_time
        alert["notified"] = True
        alert["suppressed_repeats"] = repeats
        repeat_text = ""
        if repeats > 0:
            repeat_text = f" (+{repeats} similar since last notice)"
        now_str = datetime.now().strftime("%H:%M:%S")
        print(f"[{now_str}] ALERT: {console_text}{repeat_text}")
    else:
        suppressed_counts[key] = suppressed_counts[key] + 1
        alert["notified"] = False
    log_alert(alert)
    return notify

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

def reset_live_state():
    frag_alerted.clear()
    port_history.clear()
    slow_scan_alerted.clear()
    dest_history.clear()
    dest_scan_alerted.clear()
    slowloris_windows.clear()
    slowloris_alerted.clear()
    last_notified_time.clear()
    suppressed_counts.clear()

def report_stealth_scans(packets, window_time):
    stealth_input = extract_tcp_info(packets)
    stealth_alerts = detect_stealth_scans(stealth_input)
    stealth_sources = set()
    for stealth in stealth_alerts:
        src = stealth["src"]
        stealth_sources.add(src)
        dst_list = stealth["dsts"]
        if len(dst_list) == 1:
            dst = dst_list[0]
        else:
            dst = "multiple"
        types_text = ",".join(stealth["scan_types"])
        packet_count = stealth["packets"]
        port_count = stealth["ports"]
        desc = f"STEALTH SCAN ({types_text}, {packet_count} packets, {port_count} ports)"
        timestamp = datetime.now().isoformat()
        alert = {"timestamp": timestamp, "kind": "stealth_scan", "description": desc, "source": src, "destination": dst, "num_flows": packet_count, "num_ports": port_count, "model_verdict": "stealth_scan", "confidence": None}
        emit_alert(alert, f"{desc} {src} -> {dst}", window_time)
    return stealth_sources

def flows_per_port(num_flows, num_ports):
    if num_ports == 0:
        return 0.0
    return num_flows / num_ports

def choose_campaign_label(main_verdict, num_flows, num_ports):
    ratio = flows_per_port(num_flows, num_ports)
    looks_like_flood = ratio >= FLOOD_MIN_FLOWS_PER_PORT
    looks_like_scan = ratio <= SCAN_MAX_FLOWS_PER_PORT
    few_ports = num_ports <= FEW_PORTS_MAX
    enough_attack_flows = num_flows > MIN_ATTACK_FLOWS
    enough_suspicious_flows = num_flows >= SUSPICIOUS_MIN_FLOWS
    if main_verdict == ANOMALY_VERDICT and enough_suspicious_flows:
        return "anomaly", f"ANOMALY ({num_flows} unusual flows, {num_ports} ports)"
    if main_verdict == "udp_scan" and enough_suspicious_flows:
        return "udp_scan", f"UDP SCAN({num_ports} ports)"
    if main_verdict == "syn_flood" and enough_attack_flows and few_ports:
        return "syn_flood", f"SYN FLOOD ({num_flows} half-open)"
    if main_verdict == DOS_VERDICT and enough_attack_flows:
        if few_ports or looks_like_flood:
            return "dos", f"DoS FLOOD ({num_flows} flows)"
    if main_verdict == SCAN_VERDICT and enough_suspicious_flows and looks_like_scan:
        return "port_scan", f"PORT SCAN({num_ports} ports)"
    if num_ports >= SCAN_MIN_PORTS:
        return "port_scan", f"PORT SCAN({num_ports} ports)"
    if enough_attack_flows and few_ports:
        return "brute_force", f"BRUTE FORCE ({num_flows} attempts)"
    if enough_suspicious_flows:
        return "suspicious", f"{num_flows} suspicious flows"
    return None, None

def analyze_window(packets):
    if len(packets) == 0:
        return
    window_time = float(packets[0].time)
    for src, dst, count in trackers.fragment_alerts(packets):
        pair = (src, dst)
        if pair not in frag_alerted:
            frag_alerted.add(pair)
            timestamp = datetime.now().isoformat()
            desc = f"FRAGMENTED SCAN ({count} fragments - evasion attempt)"
            alert = {"timestamp": timestamp, "kind": "fragmented_scan", "description": desc, "source": src, "destination": dst, "num_flows": count, "num_ports": 0, "model_verdict": "fragmented_scan", "confidence": None}
            emit_alert(alert, f"{desc} {src} -> {dst}", window_time)
    for src, dst, count in trackers.icmp_flood_alerts(packets):
        timestamp = datetime.now().isoformat()
        desc = f"ICMP FLOOD ({count} packets)"
        alert = {"timestamp": timestamp, "kind": "icmp_flood", "description": desc, "source": src, "destination": dst, "num_flows": count, "num_ports": 0, "model_verdict": "icmp_flood", "confidence": None}
        emit_alert(alert, f"{desc} {src} -> {dst}", window_time)
    stealth_sources = report_stealth_scans(packets, window_time)
    flows = defaultdict(list)
    for p in packets:
        info = get_ips_ports(p)
        if info is not None:
            flows[flow_key(info)].append(p)
    if not flows:
        return
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
        is_attack = (clf_verdict != NORMAL_LABEL) or (anom_verdict == -1)
        src, dst, sport, dport, proto = get_ips_ports(pkts[0])
        flags_of_first = first_tcp_flags(pkts[0])
        is_scan_probe = trackers.counts_as_scan_probe(flags_of_first)
        if is_scan_probe:
            slow = check_slow_scan(src, dst, dport)
            if slow is not None:
                desc = f"SLOW PORT SCAN ({slow} ports over time)"
                alert = {"timestamp": datetime.now().isoformat(), "kind": "slow_scan", "description": desc, "source": src, "destination": dst, "num_flows": slow, "num_ports": slow, "model_verdict": "slow_scan", "confidence": None}
                emit_alert(alert, f"{desc} {src} -> {dst}", window_time)
            dscan = check_dest_scan(dst, dport)
            if dscan is not None:
                desc = f"DISTRIBUTED SCAN ({dscan} ports on target)"
                alert = {"timestamp": datetime.now().isoformat(), "kind": "distributed_scan", "description": desc, "source": "multiple", "destination": dst, "num_flows": dscan, "num_ports": dscan, "model_verdict": "distributed_scan", "confidence": None}
                emit_alert(alert, f"DISTRIBUTED SCAN ({dscan} ports on target, multiple sources) -> {dst}", window_time)
        if is_attack:
            pair = (src, dst)
            campaigns[pair]["ports"].add(dport)
            campaigns[pair]["count"] += 1
            if clf_verdict != NORMAL_LABEL:
                reason = clf_verdict
            else:
                reason = ANOMALY_VERDICT
            campaigns[pair]["verdicts"][reason] += 1
            if clf_verdict != NORMAL_LABEL:
                campaigns[pair]["confidences"].append(confidence)
    for (src, dst), data in campaigns.items():
        num_ports = len(data["ports"])
        num_flows = data["count"]
        main_verdict = data["verdicts"].most_common(1)[0][0]
        kind, desc = choose_campaign_label(main_verdict, num_flows, num_ports)
        if kind is None:
            continue
        is_udp_scan = kind == "udp_scan"
        is_stealth_source = src in stealth_sources
        if is_udp_scan and is_stealth_source:
            continue
        confidence = average_confidence(data["confidences"])
        if confidence is not None and confidence < MODEL_ALERT_MIN_CONFIDENCE:
            continue
        timestamp = datetime.now().isoformat()
        confidence_text = ""
        if confidence is not None:
            confidence_text = f" conf={confidence:.2f}"
        alert = {"timestamp": timestamp, "kind": kind, "description": desc, "source": src, "destination": dst, "num_flows": num_flows, "num_ports": num_ports, "model_verdict": main_verdict, "confidence": confidence}
        emit_alert(alert, f"{desc} {src} -> {dst} (model: {main_verdict}{confidence_text})", window_time)
    for triple, count in trackers.slowloris_candidates(flow_list):
        slowloris_windows[triple] = slowloris_windows[triple] + 1
        if (slowloris_windows[triple] >= trackers.SLOWLORIS_MIN_WINDOWS
                and triple not in slowloris_alerted):
            slowloris_alerted.add(triple)
            host_a, host_b, port = triple
            timestamp = datetime.now().isoformat()
            desc = f"SLOWLORIS ({count} slow connections on port {port})"
            alert = {"timestamp": timestamp, "kind": "slowloris", "description": desc, "source": host_a, "destination": host_b, "num_flows": count, "num_ports": 1, "model_verdict": "slowloris", "confidence": None}
            emit_alert(alert, f"{desc} {host_a} <-> {host_b}", window_time)

def run_live():
    global INTERFACE
    INTERFACE = active_interface(ROUTER_IP)
    print(f"Auto-detected interface: {INTERFACE}")
    load_models()
    print(f"Live IDS running on {INTERFACE}, {WINDOW_SECONDS}s windows, " f"notification cooldown {ALERT_COOLDOWN_SECONDS}s\n")
    try:
        while True:
            packets = sniff(iface=INTERFACE, timeout=WINDOW_SECONDS, filter="tcp or udp or icmp")
            analyze_window(packets)
    except KeyboardInterrupt:
        print("\nStopped")

if __name__ == "__main__":
    run_live()