import joblib
import pandas as pd
import json
import trackers
import os
import sys
from scapy.all import sniff, conf, IP, rdpcap, TCP
from collections import Counter, defaultdict
from datetime import datetime
from sklearn.ensemble import IsolationForest
from features import get_ips_ports, flow_key, compute_rich_features
from context import CONTEXT_FEATURES, compute_context
from feature_sets import clean_features
from net_iface import active_interface, ROUTER_IP
from trackers import detect_stealth_scans
from scenarios import CAPTURES
from trackers import detect_stealth_scans, detect_ack_scans, is_lone_ack_probe

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
SESSION_SUFFIX = ".session.json"
SESSION_SAVE_EVERY_WINDOWS = 60
EMPTY_WINDOWS_WARNING = 12
ALERT_LOG = "alerts.jsonl"
NORMAL_LABEL = "normal"
ANOMALY_VERDICT = "anomaly"
SCAN_VERDICT = "scan"
DOS_VERDICT = "dos"
FLOOD_MIN_FLOWS_PER_PORT = 5
SCAN_MAX_FLOWS_PER_PORT = 3
NORMAL_FLOWS_CSV = "soak_normal_train.csv"
FLOW_METADATA_COLUMNS = ["window_time", "is_ipv6"]
ANOMALY_CONTAMINATION = 0.05
ANOMALY_RANDOM_SEED = 42
ALERT_COOLDOWN_SECONDS = 60
last_notified_time = {}
last_notified_specificity = {}
unsure_verdicts = {}
suppressed_kinds = defaultdict(Counter)
KIND_FAMILY = {
    "port_scan": "recon",
    "slow_scan": "recon",
    "distributed_scan": "recon",
    "udp_scan": "recon",
    "stealth_scan": "evasion",
    "fragmented_scan": "evasion",
    "ack_scan": "evasion",
    "brute_force": "access",
    "dos": "flood",
    "syn_flood": "flood",
    "icmp_flood": "flood",
    "slowloris": "flood",
    "anomaly": "anomaly",
    "suspicious": "unclassified",
}
FAMILY_COVERS = {
    "evasion": ["recon"],
}
HEADER_WORD_BYTES = 4
SPECIFICITY_GENERIC = 1
SPECIFICITY_SPECIFIC = 2
GENERIC_KINDS = ["slow_scan", "distributed_scan", "suspicious"]
FRAGMENT_EPISODE_GAP_SECONDS = 60
SLOWLORIS_EPISODE_GAP_SECONDS = 60
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

def tcp_payload_length(pkt):
    ip_header_bytes = pkt[IP].ihl * HEADER_WORD_BYTES
    tcp_header_bytes = pkt[TCP].dataofs * HEADER_WORD_BYTES
    payload_length = pkt[IP].len - ip_header_bytes - tcp_header_bytes
    return payload_length

def flow_ack_probe(pkts):
    first = pkts[0]
    if not (IP in first and TCP in first):
        return None
    initiator = first[IP].src
    packet_infos = []
    for pkt in pkts:
        if not (IP in pkt and TCP in pkt):
            continue
        from_initiator = pkt[IP].src == initiator
        flags = int(pkt[TCP].flags)
        payload_length = tcp_payload_length(pkt)
        packet_infos.append((from_initiator, flags, payload_length))
    is_probe = is_lone_ack_probe(packet_infos)
    return (first[IP].src, first[IP].dst, first[TCP].dport, is_probe)

def slowloris_triple(info):
    src, dst, sport, dport, proto = info
    hosts = sorted([src, dst])
    server_port = min(sport, dport)
    return (hosts[0], hosts[1], server_port)

def slowloris_flow_summaries(flows):
    summaries = []
    for key, pkts in flows.items():
        first = pkts[0]
        if not (IP in first and TCP in first):
            continue
        info = get_ips_ports(first)
        initiator = first[IP].src
        initiator_ack = False
        closed = False
        for pkt in pkts:
            if not (IP in pkt and TCP in pkt):
                continue
            base_flags = int(pkt[TCP].flags) & trackers.TCP_BASE_FLAGS_MASK
            from_initiator = pkt[IP].src == initiator
            has_ack = (base_flags & trackers.TCP_ACK) != 0
            if from_initiator and has_ack:
                initiator_ack = True
            is_fin = (base_flags & trackers.TCP_FIN) != 0
            is_rst = (base_flags & trackers.TCP_RST) != 0
            if is_fin or is_rst:
                closed = True
        summary = {"triple": slowloris_triple(info), "conn": key, "packets": len(pkts), "initiator_ack": initiator_ack, "closed": closed}
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

def cooldown_allows(last_time, now, cooldown_seconds):
    if last_time is None:
        return True
    elapsed = now - last_time
    if elapsed >= cooldown_seconds:
        return True
    return False

def family_of(kind):
    family = KIND_FAMILY.get(kind)
    if family is None:
        return kind
    return family

def families_that_block(family):
    blocking = [family]
    for covering_family, covered_list in FAMILY_COVERS.items():
        if family in covered_list:
            blocking.append(covering_family)
    return blocking

def specificity_of(kind):
    if kind in GENERIC_KINDS:
        return SPECIFICITY_GENERIC
    return SPECIFICITY_SPECIFIC

def format_suppressed(kind_counts):
    parts = []
    for kind in sorted(kind_counts):
        count = kind_counts[kind]
        parts.append(kind + " x" + str(count))
    return ", ".join(parts)

def unsure_context(src, dst):
    entry = unsure_verdicts.get((src, dst))
    if entry is None:
        return "", None
    verdict, confidence = entry
    text = f" [model unsure: {verdict} {confidence:.2f}]"
    field = {"verdict": verdict, "confidence": confidence}
    return text, field

def episode_starts(last_seen, now, gap_seconds):
    if last_seen is None:
        return True
    pause = now - last_seen
    if pause > gap_seconds:
        return True
    return False

def emit_alert(alert, console_text, window_time):
    source = alert["source"]
    destination = alert["destination"]
    kind = alert["kind"]
    family = family_of(kind)
    specificity = specificity_of(kind)
    alert["family"] = family
    blocking_key = None
    is_upgrade = False
    for candidate_family in families_that_block(family):
        candidate_key = (source, destination, candidate_family)
        last_time = last_notified_time.get(candidate_key)
        if cooldown_allows(last_time, window_time, ALERT_COOLDOWN_SECONDS):
            continue
        shown_specificity = last_notified_specificity.get(candidate_key, SPECIFICITY_GENERIC)
        if specificity > shown_specificity:
            is_upgrade = True
            continue
        blocking_key = candidate_key
        break
    if blocking_key is None:
        own_key = (source, destination, family)
        silent_kinds = suppressed_kinds[own_key]
        repeats = 0
        for silent_kind in silent_kinds:
            repeats = repeats + silent_kinds[silent_kind]
        repeat_text = ""
        if repeats > 0:
            repeat_text = f" (+{repeats} similar since last notice: {format_suppressed(silent_kinds)})"
        upgrade_text = ""
        if is_upgrade:
            upgrade_text = " [more specific than the earlier notice]"
        alert["notified"] = True
        alert["upgrade"] = is_upgrade
        alert["suppressed_repeats"] = repeats
        alert["suppressed_kinds"] = dict(silent_kinds)
        suppressed_kinds[own_key] = Counter()
        last_notified_time[own_key] = window_time
        last_notified_specificity[own_key] = specificity
        now_str = datetime.now().strftime("%H:%M:%S")
        print(f"[{now_str}] ALERT: {console_text}{upgrade_text}{repeat_text}")
        notify = True
    else:
        suppressed_kinds[blocking_key][kind] = suppressed_kinds[blocking_key][kind] + 1
        alert["notified"] = False
        notify = False
    log_alert(alert)
    return notify

def pending_specificity(item):
    alert = item[0]
    return specificity_of(alert["kind"])

def flush_window_alerts(pending, window_time):
    ordered = sorted(pending, key=pending_specificity, reverse=True)
    for alert, console_text in ordered:
        if alert["confidence"] is None:
            suffix, field = unsure_context(alert["source"], alert["destination"])
            if field is not None:
                alert["model_unsure"] = field
                console_text = console_text + suffix
        emit_alert(alert, console_text, window_time)

def check_slow_scan(src, dst, dport, now):
    key = (src, dst)
    port_history[key].append((dport, now))
    port_history[key] = [(p, t) for (p, t) in port_history[key] if now - t < SLOW_SCAN_WINDOW]
    distinct_ports = len(set(p for (p, t) in port_history[key]))
    if distinct_ports < SLOW_SCAN_THRESHOLD:
        slow_scan_alerted.discard(key)
        return None
    if key in slow_scan_alerted:
        return None
    slow_scan_alerted.add(key)
    return distinct_ports

def check_dest_scan(dst, dport, now):
    dest_history[dst].append((dport, now))
    dest_history[dst] = [(p, t) for (p, t) in dest_history[dst] if now - t < SLOW_SCAN_WINDOW]
    distinct_ports = len(set(p for (p, t) in dest_history[dst]))
    if distinct_ports < DEST_SCAN_THRESHOLD:
        dest_scan_alerted.discard(dst)
        return None
    if dst in dest_scan_alerted:
        return None
    dest_scan_alerted.add(dst)
    return distinct_ports

def reset_live_state():
    port_history.clear()
    slow_scan_alerted.clear()
    dest_history.clear()
    dest_scan_alerted.clear()
    slowloris_windows.clear()
    slowloris_alerted.clear()
    frag_last_seen.clear()
    slowloris_last_seen.clear()
    slowloris_previous_conns.clear()
    last_notified_time.clear()
    last_notified_specificity.clear()
    unsure_verdicts.clear()
    suppressed_kinds.clear()

def report_stealth_scans(packets, pending):
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
        pending.append((alert, f"{desc} {src} -> {dst}"))
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
    pending = []
    collect_window_alerts(packets, window_time, pending)
    flush_window_alerts(pending, window_time)

def collect_window_alerts(packets, window_time, pending):
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
    stealth_sources = report_stealth_scans(packets, pending)
    flows = defaultdict(list)
    for p in packets:
        info = get_ips_ports(p)
        if info is not None:
            flows[flow_key(info)].append(p)
    if not flows:
        return
    flow_list = list(flows.values())
    ack_sources = report_ack_scans(flow_list, pending)
    evasion_sources = set(stealth_sources)
    for ack_source in ack_sources:
        evasion_sources.add(ack_source)
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
            slow = check_slow_scan(src, dst, dport, window_time)
            if slow is not None:
                desc = f"SLOW PORT SCAN ({slow} ports over time)"
                alert = {"timestamp": datetime.now().isoformat(), "kind": "slow_scan", "description": desc, "source": src, "destination": dst, "num_flows": slow, "num_ports": slow, "model_verdict": "slow_scan", "confidence": None}
                pending.append((alert, f"{desc} {src} -> {dst}"))
            dscan = check_dest_scan(dst, dport, window_time)
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
            unsure_verdicts[(src, dst)] = (main_verdict, confidence)
            continue
        timestamp = datetime.now().isoformat()
        confidence_text = ""
        if confidence is not None:
            confidence_text = f" conf={confidence:.2f}"
        alert = {"timestamp": timestamp, "kind": kind, "description": desc, "source": src, "destination": dst, "num_flows": num_flows, "num_ports": num_ports, "model_verdict": main_verdict, "confidence": confidence}
        pending.append((alert, f"{desc} {src} -> {dst} (model: {main_verdict}{confidence_text})"))
    summaries = slowloris_flow_summaries(flows)
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