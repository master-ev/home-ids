import json
import os
import sys
from datetime import datetime
from scapy.utils import PcapReader
import live_ids

PROGRESS_EVERY_WINDOWS = 120

def parse_after_argument(argv):
    if "--after" not in argv:
        return None
    flag_index = argv.index("--after")
    value_index = flag_index + 1
    if value_index >= len(argv):
        print("Usage: ... soak_replay.py capture.pcapng log.jsonl [--after EPOCH]")
        sys.exit(1)
    return float(argv[value_index])

def to_iso(timestamp):
    return datetime.fromtimestamp(timestamp).isoformat()

def build_session(first_time, last_time, windows, packets, capture_name):
    return {
        "start": to_iso(first_time),
        "last_update": to_iso(last_time),
        "end": to_iso(last_time),
        "windows": windows,
        "packets": packets,
        "interface": "replay:" + capture_name,
    }

def main():
    if len(sys.argv) < 3:
        print("Usage: venv/bin/python soak_replay.py capture.pcapng soak_log.jsonl")
        return
    capture_path = sys.argv[1]
    log_path = sys.argv[2]
    after_time = parse_after_argument(sys.argv)
    live_ids.load_models()
    live_ids.reset_live_state()
    if os.path.exists(log_path):
        os.remove(log_path)
    live_ids.ALERT_LOG = log_path
    window = []
    window_start = None
    first_time = None
    last_time = None
    windows = 0
    packets = 0
    with PcapReader(capture_path) as reader:
        for pkt in reader:
            pkt_time = float(pkt.time)
            if after_time is not None and pkt_time < after_time:
                continue
            pkt_time = float(pkt.time)
            if first_time is None:
                first_time = pkt_time
                window_start = pkt_time
            last_time = pkt_time
            packets = packets + 1
            elapsed = pkt_time - window_start
            if elapsed >= live_ids.WINDOW_SECONDS:
                live_ids.analyze_window(window)
                windows = windows + 1
                is_progress_time = windows % PROGRESS_EVERY_WINDOWS == 0
                if is_progress_time:
                    print(f"... {windows} windows, {packets} packets")
                window = []
                window_start = pkt_time
            window.append(pkt)
    if len(window) > 0:
        live_ids.analyze_window(window)
        windows = windows + 1
    if first_time is None:
        print("[!] The capture has no packets.")
        return
    session = build_session(first_time, last_time, windows, packets, os.path.basename(capture_path))
    session_path = log_path + live_ids.SESSION_SUFFIX
    with open(session_path, "w") as f:
        json.dump(session, f, indent=2)
    print(f"Done: {windows} windows, {packets} packets -> {log_path}, {session_path}")

if __name__ == "__main__":
    main()