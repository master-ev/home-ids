import os
from collections import defaultdict
import pandas as pd
from scapy.all import rdpcap
from sklearn.ensemble import IsolationForest
from features import get_ips_ports, flow_key, compute_rich_features
from scenarios import CAPTURES

NORMAL_LABEL = "normal"
BASELINE_CAPTURE = "normal.pcap"
BASELINE_CONTAMINATION = 0.15
CONTAMINATION_VALUES = [0.15, 0.05, 0.01]
RANDOM_SEED = 42
ANOMALY_PREDICTION = -1
PERCENT = 100
NAME_WIDTH = 22
COLUMN_WIDTH = 12
HOLDOUT_NORMALS = ["dns_normal.pcap", "frag_normal.pcap"]
UNSEEN_ATTACKS = ["stealth_sX.pcap", "frag_scan.pcap", "slowloris1.pcap"]

def capture_to_rows(path):
    packets = rdpcap(path)
    flows = defaultdict(list)
    for p in packets:
        info = get_ips_ports(p)
        if info:
            flows[flow_key(info)].append(p)
    rows = []
    for key in flows:
        pkts = flows[key]
        feats = compute_rich_features(pkts)
        first_info = get_ips_ports(pkts[0])
        feats["destination_port"] = first_info[3]
        rows.append(feats)
    return pd.DataFrame(rows)

def fit_forest(frames, contamination):
    training = pd.concat(frames, ignore_index=True)
    training = training.fillna(0)
    columns = list(training.columns)
    model = IsolationForest(contamination=contamination, random_state=RANDOM_SEED)
    model.fit(training[columns])
    return model, columns

def flag_rate(model, columns, frame):
    total = len(frame)
    if total == 0:
        return None
    aligned = frame.reindex(columns=columns, fill_value=0)
    aligned = aligned.fillna(0)
    predictions = model.predict(aligned)
    flagged = 0
    for value in predictions:
        if value == ANOMALY_PREDICTION:
            flagged = flagged + 1
    return flagged * PERCENT / total

def format_rate(rate):
    if rate is None:
        return "-".rjust(COLUMN_WIDTH)
    text = f"{rate:.1f}%"
    return text.rjust(COLUMN_WIDTH)

def load_all(paths):
    frames = {}
    for path in paths:
        if not os.path.exists(path):
            print("[!] missing, skipped: " + path)
            continue
        frames[path] = capture_to_rows(path)
        print(f"loaded {path}: {len(frames[path])} flows")
    return frames

def print_header(title):
    header = "capture".ljust(NAME_WIDTH) + "baseline".rjust(COLUMN_WIDTH)
    for contamination in CONTAMINATION_VALUES:
        header = header + ("all c=" + str(contamination)).rjust(COLUMN_WIDTH)
    print()
    print(title)
    print(header)

def main():
    normal_paths = []
    for capture_name, label in CAPTURES:
        if label == NORMAL_LABEL:
            normal_paths.append(capture_name)
    normal_frames = load_all(normal_paths)
    holdout_frames = load_all(HOLDOUT_NORMALS)
    attack_frames = load_all(UNSEEN_ATTACKS)
    baseline_model, baseline_columns = fit_forest([normal_frames[BASELINE_CAPTURE]], BASELINE_CONTAMINATION)
    all_frames = []
    for path in normal_frames:
        all_frames.append(normal_frames[path])
    full_models = {}
    for contamination in CONTAMINATION_VALUES:
        full_models[contamination] = fit_forest(all_frames, contamination)
    print_header("NORMAL captures (all-normal columns = leave-one-capture-out)")
    for held_out in normal_frames:
        line = held_out.ljust(NAME_WIDTH)
        baseline_rate = flag_rate(baseline_model, baseline_columns, normal_frames[held_out])
        line = line + format_rate(baseline_rate)
        other_frames = []
        for path in normal_frames:
            if path != held_out:
                other_frames.append(normal_frames[path])
        for contamination in CONTAMINATION_VALUES:
            model, columns = fit_forest(other_frames, contamination)
            rate = flag_rate(model, columns, normal_frames[held_out])
            line = line + format_rate(rate)
        print(line)
    print_header("HOLDOUT normal captures (lower is better)")
    for path in holdout_frames:
        line = path.ljust(NAME_WIDTH)
        line = line + format_rate(flag_rate(baseline_model, baseline_columns, holdout_frames[path]))
        for contamination in CONTAMINATION_VALUES:
            model, columns = full_models[contamination]
            line = line + format_rate(flag_rate(model, columns, holdout_frames[path]))
        print(line)
    print_header("UNSEEN attacks (higher = still reacts to novelty)")
    for path in attack_frames:
        line = path.ljust(NAME_WIDTH)
        line = line + format_rate(flag_rate(baseline_model, baseline_columns, attack_frames[path]))
        for contamination in CONTAMINATION_VALUES:
            model, columns = full_models[contamination]
            line = line + format_rate(flag_rate(model, columns, attack_frames[path]))
        print(line)

if __name__ == "__main__":
    main()