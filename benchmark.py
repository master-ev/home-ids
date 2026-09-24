import os
import sys
import time
from collections import defaultdict
from scapy.all import rdpcap
import live_ids
from features import get_ips_ports, flow_key, compute_rich_features
from context import compute_context
from replay import split_into_windows

NAME_WIDTH = 24
MILLISECONDS = 1000

def time_of(function, *arguments):
    started = time.perf_counter()
    result = function(*arguments)
    elapsed = time.perf_counter() - started
    return result, elapsed

def build_flows(window):
    flows = defaultdict(list)
    for p in window:
        info = get_ips_ports(p)
        if info is not None:
            flows[flow_key(info)].append(p)
    return flows

def features_of(flow_list):
    rows = []
    for pkts in flow_list:
        feats = compute_rich_features(pkts)
        feats["destination_port"] = get_ips_ports(pkts[0])[3]
        rows.append(feats)
    return rows

def predict_all(flow_list, rows):
    import pandas as pd
    from feature_sets import clean_features
    verdicts = []
    for row in rows:
        frame = pd.DataFrame([{n: row.get(n, 0) for n in live_ids.clf_features_v2}])[live_ids.clf_features_v2]
        frame = clean_features(frame)
        probabilities = live_ids.classifier_v2.predict_proba(frame)[0]
        verdicts.append(probabilities.argmax())
    return verdicts

def benchmark(path):
    packets = rdpcap(path)
    windows = split_into_windows(packets, live_ids.WINDOW_SECONDS)
    total_packets = len(packets)
    flow_time = 0.0
    feature_time = 0.0
    context_time = 0.0
    model_time = 0.0
    whole_time = 0.0
    total_flows = 0
    slowest_window = 0.0
    for window in windows:
        flows, elapsed = time_of(build_flows, window)
        flow_time = flow_time + elapsed
        flow_list = list(flows.values())
        total_flows = total_flows + len(flow_list)
        if len(flow_list) == 0:
            continue
        rows, elapsed = time_of(features_of, flow_list)
        feature_time = feature_time + elapsed
        ignored, elapsed = time_of(compute_context, flow_list)
        context_time = context_time + elapsed
        ignored, elapsed = time_of(predict_all, flow_list, rows)
        model_time = model_time + elapsed
    live_ids.reset_live_state()
    original_log = live_ids.ALERT_LOG
    live_ids.ALERT_LOG = "/dev/null"
    for window in windows:
        ignored, elapsed = time_of(live_ids.analyze_window, window)
        whole_time = whole_time + elapsed
        if elapsed > slowest_window:
            slowest_window = elapsed
    live_ids.ALERT_LOG = original_log
    window_count = len(windows)
    if window_count == 0 or whole_time == 0:
        print(path + " no windows")
        return
    packets_per_second = total_packets / whole_time
    capture_seconds = window_count * live_ids.WINDOW_SECONDS
    real_time_margin = capture_seconds / whole_time
    print(path)
    print(f"  packets={total_packets}  flows={total_flows}  windows={window_count}")
    print(f"  {'flow grouping':<{NAME_WIDTH}} {flow_time * MILLISECONDS:8.1f} ms")
    print(f"  {'feature extraction':<{NAME_WIDTH}} {feature_time * MILLISECONDS:8.1f} ms")
    print(f"  {'context features':<{NAME_WIDTH}} {context_time * MILLISECONDS:8.1f} ms")
    print(f"  {'model prediction':<{NAME_WIDTH}} {model_time * MILLISECONDS:8.1f} ms")
    print(f"  {'WHOLE pipeline':<{NAME_WIDTH}} {whole_time * MILLISECONDS:8.1f} ms")
    print(f"  slowest single window: {slowest_window * MILLISECONDS:.1f} ms " f"(budget {live_ids.WINDOW_SECONDS * MILLISECONDS:.0f} ms)")
    print(f"  throughput: {packets_per_second:.0f} packets/s")
    print(f"  real-time margin: {real_time_margin:.1f}x")
    print()

def main():
    if len(sys.argv) < 2:
        print("Usage: venv/bin/python benchmark.py capture1.pcap [...]")
        return
    live_ids.load_models()
    for path in sys.argv[1:]:
        if not os.path.exists(path):
            print("[!] missing: " + path)
            continue
        benchmark(path)

if __name__ == "__main__":
    main()