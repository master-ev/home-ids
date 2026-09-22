import os
import sys
from collections import defaultdict
import pandas as pd
from scapy.utils import PcapReader
from scapy.all import IPv6
import live_ids
from features import get_ips_ports, flow_key, compute_rich_features

TRAIN_CSV = "soak_normal_train.csv"
HOLDOUT_CSV = "soak_normal_holdout.csv"
SPLIT_FRACTION = 0.5
PROGRESS_EVERY_WINDOWS = 200

def window_rows(window, window_time):
    rows = []
    flows = defaultdict(list)
    for p in window:
        info = get_ips_ports(p)
        if info is not None:
            flows[flow_key(info)].append(p)
    for key in flows:
        pkts = flows[key]
        feats = compute_rich_features(pkts)
        feats["destination_port"] = get_ips_ports(pkts[0])[3]
        feats["window_time"] = window_time
        if IPv6 in pkts[0]:
            feats["is_ipv6"] = 1
        else:
            feats["is_ipv6"] = 0
        rows.append(feats)
    return rows

def collect_rows(capture_path):
    rows = []
    window = []
    window_start = None
    windows = 0
    for_reader = PcapReader(capture_path)
    with for_reader as reader:
        for pkt in reader:
            pkt_time = float(pkt.time)
            if window_start is None:
                window_start = pkt_time
            elapsed = pkt_time - window_start
            if elapsed >= live_ids.WINDOW_SECONDS:
                rows.extend(window_rows(window, window_start))
                windows = windows + 1
                if windows % PROGRESS_EVERY_WINDOWS == 0:
                    print(f"... {windows} windows, {len(rows)} flows")
                window = []
                window_start = pkt_time
            window.append(pkt)
    if len(window) > 0:
        rows.extend(window_rows(window, window_start))
    return rows

def split_by_time(frame, fraction):
    ordered = frame.sort_values("window_time")
    split_index = int(len(ordered) * fraction)
    train = ordered.iloc[:split_index]
    holdout = ordered.iloc[split_index:]
    split_time = float(holdout["window_time"].iloc[0])
    return train, holdout, split_time

def main():
    if len(sys.argv) < 2:
        print("Usage: venv/bin/python build_normal_flows.py capture.pcapng")
        return
    capture_path = sys.argv[1]
    if not os.path.exists(capture_path):
        print("[!] Missing capture: " + capture_path)
        return
    rows = collect_rows(capture_path)
    if len(rows) == 0:
        print("[!] No flows found in the capture.")
        return
    frame = pd.DataFrame(rows)
    frame = frame.fillna(0)
    train, holdout, split_time = split_by_time(frame, SPLIT_FRACTION)
    train.to_csv(TRAIN_CSV, index=False)
    holdout.to_csv(HOLDOUT_CSV, index=False)
    ipv6_share = frame["is_ipv6"].mean()
    print(f"Total flows: {len(frame)}   IPv6 share: {ipv6_share:.1%}")
    print(f"Train: {len(train)} flows -> {TRAIN_CSV}")
    print(f"Holdout: {len(holdout)} flows -> {HOLDOUT_CSV}")
    print(f"Holdout starts at epoch {split_time:.3f}")
    print(f"Replay the holdout half with: venv/bin/python soak_replay.py {capture_path} <log.jsonl> --after {split_time:.3f}")

if __name__ == "__main__":
    main()