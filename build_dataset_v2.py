from collections import defaultdict
import pandas as pd
from scapy.all import rdpcap
from context import CONTEXT_FEATURES, compute_context
from feature_sets import MISSING_VALUE, load_base_features
from features import compute_rich_features, flow_key, get_ips_ports
from scenarios import CAPTURES
from feature_sets import MISSING_VALUE, load_base_features, PROTOCOL_FEATURES

OUTPUT_PATH = "my_dataset_v2.csv"
LABEL_COLUMN = "label"
CAPTURE_COLUMN = "capture"
PORT_INDEX = 3
MAX_FLOWS_PER_CAPTURE = 3000
SAMPLE_SEED = 42

def load_flows(path):
    packets = rdpcap(path)
    flows = defaultdict(list)
    for packet in packets:
        info = get_ips_ports(packet)
        if info is not None:
            key = flow_key(info)
            flows[key].append(packet)
    return list(flows.values())

def featurize_flows(flow_list, base_features):
    context_rows = compute_context(flow_list)
    rows = []
    for index in range(len(flow_list)):
        packets = flow_list[index]
        features = compute_rich_features(packets)
        info = get_ips_ports(packets[0])
        features["destination_port"] = info[PORT_INDEX]
        row = {}
        for name in base_features:
            row[name] = features.get(name, MISSING_VALUE)
        context = context_rows[index]
        for name in CONTEXT_FEATURES:
            row[name] = context[name]
        for name in PROTOCOL_FEATURES:
            row[name] = features.get(name, MISSING_VALUE)
        rows.append(row)
    return rows

def featurize_pcap(path, base_features):
    flow_list = load_flows(path)
    rows = featurize_flows(flow_list, base_features)
    return rows, flow_list

def main():
    base_features = load_base_features()
    all_rows = []
    for path, label in CAPTURES:
        try:
            rows, flow_list = featurize_pcap(path, base_features)
        except (FileNotFoundError, OSError):
            print(f"[!] Skipping missing capture: {path}")
            continue
        for row in rows:
            row[LABEL_COLUMN] = label
            row[CAPTURE_COLUMN] = path
            all_rows.append(row)
        print(f"{path:<18} label={label:<11} flows={len(rows)}")
        full = pd.DataFrame(all_rows)
    parts = []
    for capture_name in full[CAPTURE_COLUMN].unique():
        part = full[full[CAPTURE_COLUMN] == capture_name]
        if len(part) > MAX_FLOWS_PER_CAPTURE:
            part = part.sample(n=MAX_FLOWS_PER_CAPTURE, random_state=SAMPLE_SEED)
            print(f"{capture_name}: sampled down to {MAX_FLOWS_PER_CAPTURE} flows")
        parts.append(part)
    dataset = pd.concat(parts, ignore_index=True)
    dataset.to_csv(OUTPUT_PATH, index=False)
    print()
    print(dataset[LABEL_COLUMN].value_counts())
    print(f"Saved {len(dataset)} rows to {OUTPUT_PATH}")

if __name__ == "__main__":
    main()