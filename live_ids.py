import joblib
import pandas as pd
import json
import packet_view
import trackers
import os
import sys
import flow_state
import alert_policy
from alert_policy import (episode_starts, ALERT_COOLDOWN_SECONDS, FRAGMENT_EPISODE_GAP_SECONDS, SLOWLORIS_EPISODE_GAP_SECONDS)
from scapy.all import sniff, conf, IP, rdpcap, TCP
from collections import Counter, defaultdict
from datetime import datetime
from sklearn.ensemble import IsolationForest
from features import get_ips_ports, flow_key, compute_rich_features
from context import CONTEXT_FEATURES, compute_context
from feature_sets import clean_features
from net_iface import active_interface, ROUTER_IP
from trackers import detect_stealth_scans, detect_ack_scans, is_lone_ack_probe
from scenarios import CAPTURES
from labels import choose_campaign_label, ANOMALY_VERDICT
from batch_predict import (build_feature_frame, predict_labels_batch, predict_anomalies_batch,)

def require_file(path, hint):
    if not os.path.exists(path):
        print(f"[!] Missing required file: {path}")
        print(f"    {hint}")
        print("    Run 'venv/bin/python setup_check.py' for the full checklist.")
        sys.exit(1)

FRAGMENT_FLOOD_THRESHOLD = 30
MODEL_ALERT_MIN_CONFIDENCE = 0.70
USE_V2 = True
V2_MODEL_PATH = "my_model_v2.joblib"
ICMP_FLOOD_THRESHOLD = 100
ICMP_PROTO = "ICMP"
SLOWLORIS_MIN_CONNECTIONS = 20
SLOWLORIS_MAX_PKTS_PER_CONN = 12
SLOWLORIS_MIN_WINDOWS = 3
slowloris_windows = defaultdict(int)
slowloris_alerted = set()
conf.use_pcap = True
WINDOW_SECONDS = 5
SESSION_SUFFIX = ".session.json"
SESSION_SAVE_EVERY_WINDOWS = 60
EMPTY_WINDOWS_WARNING = 12
ALERT_LOG = "alerts.jsonl"
NORMAL_LABEL = "normal"
NORMAL_FLOWS_CSV = "soak_normal_train.csv"
FLOW_METADATA_COLUMNS = ["window_time", "is_ipv6"]
ANOMALY_CONTAMINATION = 0.05
ANOMALY_RANDOM_SEED = 42
HEADER_WORD_BYTES = 4
MISSING_FEATURE_DEFAULT = 0
frag_last_seen = {}
slowloris_last_seen = {}
slowloris_previous_conns = {}
classifier = None
clf_features = None
classifier_v2 = None
clf_features_v2 = None
anomaly_model = None
anomaly_features = None
INTERFACE = None

def extract_tcp_info(views):
    tcp_packets = []
    for view in views:
        if not packet_view.is_tcp(view):
            continue
        src = view[packet_view.VIEW_SRC]
        dst = view[packet_view.VIEW_DST]
        dport = view[packet_view.VIEW_DPORT]
        flags = view[packet_view.VIEW_FLAGS]
        tcp_packets.append((src, dst, dport, flags))
    return tcp_packets

def first_tcp_flags(pkt):
    if TCP in pkt:
        return int(pkt[TCP].flags)
    return None

def tcp_payload_length(pkt):
    ip_header_bytes = pkt[IP].ihl * HEADER_WORD_BYTES
    tcp_header_bytes = pkt[TCP].dataofs * HEADER_WORD_BYTES
    payload_length = pkt[IP].len - ip_header_bytes - tcp_header_bytes
    return payload_length

def flow_ack_probe(flow_views):
    first = flow_views[0]
    if not packet_view.is_tcp(first):
        return None
    initiator = first[packet_view.VIEW_SRC]
    packet_infos = []
    for view in flow_views:
        if not packet_view.is_tcp(view):
            continue
        from_initiator = view[packet_view.VIEW_SRC] == initiator
        flags = view[packet_view.VIEW_FLAGS]
        payload_length = view[packet_view.VIEW_PAYLOAD]
        packet_infos.append((from_initiator, flags, payload_length))
    is_probe = is_lone_ack_probe(packet_infos)
    return (first[packet_view.VIEW_SRC], first[packet_view.VIEW_DST], first[packet_view.VIEW_DPORT], is_probe)

def slowloris_triple(info):
    src, dst, sport, dport, proto = info
    hosts = sorted([src, dst])
    server_port = min(sport, dport)
    return (hosts[0], hosts[1], server_port)

def slowloris_flow_summaries(flow_views_by_key):
    summaries = []
    for key, flow_views in flow_views_by_key.items():
        first = flow_views[0]
        if not packet_view.is_tcp(first):
            continue
        src = first[packet_view.VIEW_SRC]
        dst = first[packet_view.VIEW_DST]
        sport = first[packet_view.VIEW_SPORT]
        dport = first[packet_view.VIEW_DPORT]
        info = (src, dst, sport, dport, packet_view.TCP_PROTO)
        initiator = src
        initiator_ack = False
        closed = False
        for view in flow_views:
            if not packet_view.is_tcp(view):
                continue
            base_flags = view[packet_view.VIEW_FLAGS] & trackers.TCP_BASE_FLAGS_MASK
            from_initiator = view[packet_view.VIEW_SRC] == initiator
            has_ack = (base_flags & trackers.TCP_ACK) != 0
            if from_initiator and has_ack:
                initiator_ack = True
            is_fin = (base_flags & trackers.TCP_FIN) != 0
            is_rst = (base_flags & trackers.TCP_RST) != 0
            if is_fin or is_rst:
                closed = True
        summary = {"triple": slowloris_triple(info), "conn": key, "packets": len(flow_views), "initiator_ack": initiator_ack, "closed": closed}
        summaries.append(summary)
    return summaries

def report_ack_scans(flow_list, pending):
    flow_probes = []
    for pkts in flow_list:
        probe = flow_ack_probe(pkts)
        if probe is not None:
            flow_probes.append(probe)
    ack_alerts = detect_ack_scans(flow_probes)
    ack_sources = set()
    for ack in ack_alerts:
        src = ack["src"]
        ack_sources.add(src)
        dst_list = ack["dsts"]
        if len(dst_list) == 1:
            dst = dst_list[0]
        else:
            dst = "multiple"
        desc = f"ACK SCAN ({ack['probes']} lone ACK probes, {ack['ports']} ports - firewall mapping)"
        timestamp = datetime.now().isoformat()
        alert = {"timestamp": timestamp, "kind": "ack_scan", "description": desc, "source": src, "destination": dst, "num_flows": ack["probes"], "num_ports": ack["ports"], "model_verdict": "ack_scan", "confidence": None}
        pending.append((alert, f"{desc} {src} -> {dst}"))
    return ack_sources

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

def load_extra_normal_flows(csv_path):
    frame = pd.read_csv(csv_path)
    for column in FLOW_METADATA_COLUMNS:
        if column in frame.columns:
            frame = frame.drop(columns=[column])
    return frame

def load_models():
    global classifier, clf_features, classifier_v2, clf_features_v2
    global anomaly_model, anomaly_features
    if not USE_V2:
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
    frames = [load_normal(normal_paths)]
    extra_source = "lab captures only"
    if os.path.exists(NORMAL_FLOWS_CSV):
        extra = load_extra_normal_flows(NORMAL_FLOWS_CSV)
        frames.append(extra)
        extra_source = f"lab captures + {len(extra)} real-traffic flows"
    normal = pd.concat(frames, ignore_index=True).fillna(0)
    anomaly_features = list(normal.columns)
    anomaly_model = IsolationForest(contamination=ANOMALY_CONTAMINATION, random_state=ANOMALY_RANDOM_SEED)
    anomaly_model.fit(normal[anomaly_features])
    print(f"Anomaly model: {len(normal)} flows ({extra_source}), " f"contamination={ANOMALY_CONTAMINATION}")

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

def report_stealth_scans(views, pending):
    stealth_input = extract_tcp_info(views)
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
        pending.append((alert, f"{desc} {src} -> {dst}"))
    return stealth_sources

def analyze_window(packets):
    if len(packets) == 0:
        return
    window_time = float(packets[0].time)
    pending = []
    collect_window_alerts(packets, window_time, pending)
    alert_policy.flush_window_alerts(pending, window_time, log_alert)

def reset_live_state():
    flow_state.reset_scan_state()
    alert_policy.reset_policy_state()
    slowloris_windows.clear()
    slowloris_alerted.clear()
    frag_last_seen.clear()
    slowloris_last_seen.clear()
    slowloris_previous_conns.clear()

def rows_for_feature_names(feature_dicts, feature_names):
    rows = []
    for feats in feature_dicts:
        row = {}
        for name in feature_names:
            row[name] = feats.get(name, MISSING_FEATURE_DEFAULT)
        rows.append(row)
    return rows

def prepare_window_flows(flows, flow_views_by_key, context_rows):
    prepared = []
    position = 0
    for key, pkts in flows.items():
        first_view = flow_views_by_key[key][0]
        if first_view is not None and first_view[packet_view.VIEW_PROTO] == ICMP_PROTO:
            position = position + 1
            continue
        feats = compute_rich_features(pkts)
        feats["destination_port"] = first_view[packet_view.VIEW_DPORT]
        context = context_rows[position]
        for name in CONTEXT_FEATURES:
            feats[name] = context[name]
        position = position + 1
        prepared.append((key, pkts, feats, first_view))
    return prepared

def predict_window(prepared):
    feature_dicts = []
    for key, pkts, feats, first_view in prepared:
        feature_dicts.append(feats)
    if USE_V2:
        active_features = clf_features_v2
        active_classifier = classifier_v2
    else:
        active_features = clf_features
        active_classifier = classifier
    clf_rows = rows_for_feature_names(feature_dicts, active_features)
    clf_frame = build_feature_frame(clf_rows, active_features)
    clf_frame = clean_features(clf_frame)
    predictions = predict_labels_batch(active_classifier, clf_frame)
    anom_rows = rows_for_feature_names(feature_dicts, anomaly_features)
    anom_frame = build_feature_frame(anom_rows, anomaly_features)
    anomalies = predict_anomalies_batch(anomaly_model, anom_frame)
    return predictions, anomalies

def collect_window_alerts(packets, window_time, pending):
    views = packet_view.build_views(packets)
    for src, dst, count in trackers.fragment_alerts(packets):
        pair = (src, dst)
        last_seen = frag_last_seen.get(pair)
        frag_last_seen[pair] = window_time
        new_episode = episode_starts(last_seen, window_time, FRAGMENT_EPISODE_GAP_SECONDS)
        if not new_episode:
            continue
        timestamp = datetime.now().isoformat()
        desc = f"FRAGMENTED SCAN ({count} fragments - evasion attempt)"
        alert = {"timestamp": timestamp, "kind": "fragmented_scan", "description": desc, "source": src, "destination": dst, "num_flows": count, "num_ports": 0, "model_verdict": "fragmented_scan", "confidence": None}
        pending.append((alert, f"{desc} {src} -> {dst}"))
    for src, dst, count in trackers.icmp_flood_alerts(packets):
        timestamp = datetime.now().isoformat()
        desc = f"ICMP FLOOD ({count} packets)"
        alert = {"timestamp": timestamp, "kind": "icmp_flood", "description": desc, "source": src, "destination": dst, "num_flows": count, "num_ports": 0, "model_verdict": "icmp_flood", "confidence": None}
        pending.append((alert, f"{desc} {src} -> {dst}"))
    stealth_sources = report_stealth_scans(views, pending)
    flows = defaultdict(list)
    flow_views_by_key = defaultdict(list)
    packet_index = 0
    for p in packets:
        info = get_ips_ports(p)
        if info is not None:
            key = flow_key(info)
            flows[key].append(p)
            flow_views_by_key[key].append(views[packet_index])
        packet_index = packet_index + 1
    if not flows:
        return
    flow_list = list(flows.values())
    view_list = list(flow_views_by_key.values())
    ack_sources = report_ack_scans(view_list, pending)
    evasion_sources = set(stealth_sources)
    for ack_source in ack_sources:
        evasion_sources.add(ack_source)
    context_rows = compute_context(flow_list)
    campaigns = defaultdict(lambda: {"ports": set(), "count": 0, "verdicts": Counter(), "confidences": []})
    prepared = prepare_window_flows(flows, flow_views_by_key, context_rows)
    if len(prepared) == 0:
        predictions = []
        anomalies = []
    else:
        predictions, anomalies = predict_window(prepared)
    flow_index = 0
    while flow_index < len(prepared):
        key, pkts, feats, first_view = prepared[flow_index]
        clf_verdict, confidence = predictions[flow_index]
        is_anomaly = anomalies[flow_index]
        flow_index = flow_index + 1
        is_attack = (clf_verdict != NORMAL_LABEL) or is_anomaly
        src = first_view[packet_view.VIEW_SRC]
        dst = first_view[packet_view.VIEW_DST]
        dport = first_view[packet_view.VIEW_DPORT]
        flags_of_first = first_view[packet_view.VIEW_FLAGS]
        is_scan_probe = trackers.counts_as_scan_probe(flags_of_first)
        if is_scan_probe:
            slow = flow_state.check_slow_scan(src, dst, dport, window_time)
            if slow is not None:
                desc = f"SLOW PORT SCAN ({slow} ports over time)"
                alert = {"timestamp": datetime.now().isoformat(), "kind": "slow_scan", "description": desc, "source": src, "destination": dst, "num_flows": slow, "num_ports": slow, "model_verdict": "slow_scan", "confidence": None}
                pending.append((alert, f"{desc} {src} -> {dst}"))
            dscan = flow_state.check_dest_scan(dst, dport, window_time)
            if dscan is not None:
                desc = f"DISTRIBUTED SCAN ({dscan} ports on target)"
                alert = {"timestamp": datetime.now().isoformat(), "kind": "distributed_scan", "description": desc, "source": "multiple", "destination": dst, "num_flows": dscan, "num_ports": dscan, "model_verdict": "distributed_scan", "confidence": None}
                pending.append((alert, f"DISTRIBUTED SCAN ({dscan} ports on target, multiple sources) -> {dst}"))
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
        is_evasion_source = src in evasion_sources
        if is_udp_scan and is_evasion_source:
            continue
        confidence = average_confidence(data["confidences"])
        if confidence is not None and confidence < MODEL_ALERT_MIN_CONFIDENCE:
            alert_policy.unsure_verdicts[(src, dst)] = (main_verdict, confidence)
            continue
        timestamp = datetime.now().isoformat()
        confidence_text = ""
        if confidence is not None:
            confidence_text = f" conf={confidence:.2f}"
        alert = {"timestamp": timestamp, "kind": kind, "description": desc, "source": src, "destination": dst, "num_flows": num_flows, "num_ports": num_ports, "model_verdict": main_verdict, "confidence": confidence}
        pending.append((alert, f"{desc} {src} -> {dst} (model: {main_verdict}{confidence_text})"))
    summaries = slowloris_flow_summaries(flow_views_by_key)
    current_conns = trackers.held_open_connections(summaries)
    for triple in sorted(current_conns):
        conns = current_conns[triple]
        previous_conns = slowloris_previous_conns.get(triple, set())
        slowloris_previous_conns[triple] = conns
        if len(conns) < trackers.SLOWLORIS_MIN_CONNECTIONS:
            continue
        persistent = trackers.persistent_connections(conns, previous_conns)
        if len(persistent) < trackers.SLOWLORIS_MIN_PERSISTENT:
            continue
        last_seen = slowloris_last_seen.get(triple)
        slowloris_last_seen[triple] = window_time
        if episode_starts(last_seen, window_time, SLOWLORIS_EPISODE_GAP_SECONDS):
            slowloris_windows[triple] = 0
            slowloris_alerted.discard(triple)
        slowloris_windows[triple] = slowloris_windows[triple] + 1
        enough_windows = slowloris_windows[triple] >= trackers.SLOWLORIS_MIN_WINDOWS
        if enough_windows and triple not in slowloris_alerted:
            slowloris_alerted.add(triple)
            host_a, host_b, port = triple
            timestamp = datetime.now().isoformat()
            desc = f"SLOWLORIS ({len(persistent)} connections held open on port {port})"
            alert = {"timestamp": timestamp, "kind": "slowloris", "description": desc, "source": host_a, "destination": host_b, "num_flows": len(conns), "num_ports": 1, "model_verdict": "slowloris", "confidence": None}
            pending.append((alert, f"{desc} {host_a} <-> {host_b}"))

def parse_log_argument(argv):
    if "--log" not in argv:
        return None
    flag_index = argv.index("--log")
    value_index = flag_index + 1
    if value_index >= len(argv):
        print("Usage: sudo venv/bin/python live_ids.py [--log soak_alerts.jsonl]")
        sys.exit(1)
    return argv[value_index]

def write_session(session_path, session):
    with open(session_path, "w") as f:
        json.dump(session, f, indent=2)

def run_live(log_path):
    global INTERFACE, ALERT_LOG
    INTERFACE = active_interface(ROUTER_IP)
    print(f"Auto-detected interface: {INTERFACE}")
    load_models()
    session = None
    session_path = None
    if log_path is not None:
        ALERT_LOG = log_path
        session_path = log_path + SESSION_SUFFIX
        start_text = datetime.now().isoformat()
        session = {"start": start_text, "last_update": start_text, "end": None, "windows": 0, "packets": 0, "interface": INTERFACE}
        write_session(session_path, session)
        print(f"Soak session: alerts -> {log_path}, session -> {session_path}")
    print(f"Live IDS running on {INTERFACE}, {WINDOW_SECONDS}s windows, " f"notification cooldown {ALERT_COOLDOWN_SECONDS}s per family\n")
    consecutive_empty = 0
    try:
        while True:
            packets = sniff(iface=INTERFACE, timeout=WINDOW_SECONDS, filter="tcp or udp or icmp")
            if len(packets) == 0:
                consecutive_empty = consecutive_empty + 1
                if consecutive_empty == EMPTY_WINDOWS_WARNING:
                    silent_seconds = EMPTY_WINDOWS_WARNING * WINDOW_SECONDS
                    print(f"[!] No packets for {silent_seconds}s on {INTERFACE} - is this sensor seeing any traffic? (ip route get 1.1.1.1)")
            else:
                consecutive_empty = 0
            analyze_window(packets)
            if session is not None:
                session["windows"] = session["windows"] + 1
                session["packets"] = session["packets"] + len(packets)
                is_save_time = session["windows"] % SESSION_SAVE_EVERY_WINDOWS == 0
                if is_save_time:
                    session["last_update"] = datetime.now().isoformat()
                    write_session(session_path, session)
    except KeyboardInterrupt:
        print("\nStopped")
        if session is not None:
            end_text = datetime.now().isoformat()
            session["last_update"] = end_text
            session["end"] = end_text
            write_session(session_path, session)
            print(f"Session saved: {session['windows']} windows, {session['packets']} packets")

if __name__ == "__main__":
    log_argument = parse_log_argument(sys.argv)
    run_live(log_argument)