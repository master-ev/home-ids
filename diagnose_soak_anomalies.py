from collections import defaultdict
import pandas as pd
from scapy.all import rdpcap
from sklearn.ensemble import IsolationForest
import live_ids
from features import get_ips_ports, flow_key, compute_rich_features
from build_normal_flows import TRAIN_CSV, HOLDOUT_CSV

CONTAMINATION_VALUES = [0.05, 0.01, 0.005]
RANDOM_SEED = 42
ANOMALY_PREDICTION = -1
PERCENT = 100
NAME_WIDTH = 26
COLUMN_WIDTH = 13
METADATA_COLUMNS = ["window_time", "is_ipv6"]
ATTACK_CAPTURES = ["slowloris1.pcap", "ack_scan.pcap", "stealth_sX.pcap", "dos.pcap"]

def drop_metadata(frame):
    kept = frame
    for column in METADATA_COLUMNS:
        if column in kept.columns:
            kept = kept.drop(columns=[column])
    return kept

def capture_frame(path):
    packets = rdpcap(path)
    flows = defaultdict(list)
    for p in packets:
        info = get_ips_ports(p)
        if info is not None:
            flows[flow_key(info)].append(p)
    rows = []
    for key in flows:
        pkts = flows[key]
        feats = compute_rich_features(pkts)
        feats["destination_port"] = get_ips_ports(pkts[0])[3]
        rows.append(feats)
    return pd.DataFrame(rows).fillna(0)

def fit_forest(frames, contamination):
    training = pd.concat(frames, ignore_index=True).fillna(0)
    columns = list(training.columns)
    model = IsolationForest(contamination=contamination, random_state=RANDOM_SEED)
    model.fit(training[columns])
    return model, columns

def flag_rate(model, columns, frame):
    total = len(frame)
    if total == 0:
        return None
    aligned = frame.reindex(columns=columns, fill_value=0).fillna(0)
    predictions = model.predict(aligned)
    flagged = 0
    for value in predictions:
        if value == ANOMALY_PREDICTION:
            flagged = flagged + 1
    return flagged * PERCENT / total

def format_rate(rate):
    if rate is None:
        return "-".rjust(COLUMN_WIDTH)
    return f"{rate:.1f}%".rjust(COLUMN_WIDTH)

def main():
    lab_frames = []
    for path in live_ids.normal_capture_paths():
        lab_frames.append(capture_frame(path))
    print(f"Lab normal flows: {sum(len(f) for f in lab_frames)}")
    soak_train = drop_metadata(pd.read_csv(TRAIN_CSV))
    soak_holdout = drop_metadata(pd.read_csv(HOLDOUT_CSV))
    print(f"Soak train flows: {len(soak_train)}   holdout flows: {len(soak_holdout)}")
    attack_frames = {}
    for path in ATTACK_CAPTURES:
        attack_frames[path] = capture_frame(path)
    header = "config".ljust(NAME_WIDTH) + "soak holdout".rjust(COLUMN_WIDTH)
    for path in ATTACK_CAPTURES:
        header = header + path.replace(".pcap", "").rjust(COLUMN_WIDTH)
    print()
    print("Flagged flows (lower is better on holdout, higher is better on attacks)")
    print(header)
    configs = []
    configs.append(("lab only c=0.05", lab_frames, 0.05))
    for contamination in CONTAMINATION_VALUES:
        configs.append((f"lab+soak c={contamination}", lab_frames + [soak_train], contamination))
    for name, frames, contamination in configs:
        model, columns = fit_forest(frames, contamination)
        line = name.ljust(NAME_WIDTH) + format_rate(flag_rate(model, columns, soak_holdout))
        for path in ATTACK_CAPTURES:
            line = line + format_rate(flag_rate(model, columns, attack_frames[path]))
        print(line)

if __name__ == "__main__":
    main()