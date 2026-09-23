import os
import live_ids
from replay import replay_to_log

DEMO_LOG = "demo_alerts.jsonl"
PART_LOG = "demo_part.jsonl"
DEMO_CAPTURES = [
    "scan_connect_router.pcap",
    "decoy2_router.pcap",
    "stealth_sX.pcap",
    "ack_scan.pcap",
    "frag_scan.pcap",
    "syn_flood1.pcap",
    "slowloris1.pcap",
    "bruteforce.pcap",
    "padded_200.pcap",
]

def append_alerts(source_path, target_path):
    with open(source_path) as source:
        content = source.read()
    with open(target_path, "a") as target:
        target.write(content)

def main():
    live_ids.load_models()
    if os.path.exists(DEMO_LOG):
        os.remove(DEMO_LOG)
    for capture in DEMO_CAPTURES:
        if not os.path.exists(capture):
            print("[!] missing, skipped: " + capture)
            continue
        print("Replaying " + capture + " ...")
        replay_to_log(capture, PART_LOG)
        if os.path.exists(PART_LOG):
            append_alerts(PART_LOG, DEMO_LOG)
    if os.path.exists(PART_LOG):
        os.remove(PART_LOG)
    if not os.path.exists(DEMO_LOG):
        print("[!] No alerts produced.")
        return
    with open(DEMO_LOG) as f:
        line_count = len(f.readlines())
    print(f"Demo log written to {DEMO_LOG}: {line_count} alerts")

if __name__ == "__main__":
    main()