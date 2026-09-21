import json
import os
from scapy.all import rdpcap
import live_ids

def split_into_windows(packets, window_seconds):
    windows = []
    if len(packets) == 0:
        return windows
    current = []
    window_start = float(packets[0].time)
    for pkt in packets:
        pkt_time = float(pkt.time)
        elapsed = pkt_time - window_start
        if elapsed >= window_seconds:
            windows.append(current)
            current = []
            window_start = pkt_time
        current.append(pkt)
    if len(current) > 0:
        windows.append(current)
    return windows

def read_logged_alerts(log_path):
    alerts = []
    if not os.path.exists(log_path):
        return alerts
    with open(log_path) as f:
        for line in f:
            stripped = line.strip()
            if stripped == "":
                continue
            alerts.append(json.loads(stripped))
    return alerts

def replay_to_log(capture_path, log_path):
    live_ids.reset_live_state()
    if os.path.exists(log_path):
        os.remove(log_path)
    original_log = live_ids.ALERT_LOG
    live_ids.ALERT_LOG = log_path
    try:
        packets = rdpcap(capture_path)
        windows = split_into_windows(packets, live_ids.WINDOW_SECONDS)
        for window in windows:
            live_ids.analyze_window(window)
    finally:
        live_ids.ALERT_LOG = original_log
    return read_logged_alerts(log_path)