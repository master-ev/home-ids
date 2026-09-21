import sys
from collections import defaultdict
from scapy.all import rdpcap
import live_ids
import trackers
from features import get_ips_ports, flow_key
from replay import split_into_windows

def longest_gap(times):
    longest = 0.0
    index = 1
    while index < len(times):
        gap = times[index] - times[index - 1]
        if gap > longest:
            longest = gap
        index = index + 1
    return longest

def print_activity(title, activity):
    if len(activity) == 0:
        print("  " + title + ": no activity")
        return
    for key in activity:
        times = activity[key]
        span = times[-1] - times[0]
        gap = longest_gap(times)
        print(f"  {title} {key}: active windows={len(times)}  span={span:.1f}s  longest pause={gap:.1f}s")

def diagnose(path):
    packets = rdpcap(path)
    windows = split_into_windows(packets, live_ids.WINDOW_SECONDS)
    fragment_activity = defaultdict(list)
    slowloris_activity = defaultdict(list)
    for window in windows:
        window_time = float(window[0].time)
        for src, dst, count in trackers.fragment_alerts(window):
            fragment_activity[(src, dst)].append(window_time)
        flows = defaultdict(list)
        for p in window:
            info = get_ips_ports(p)
            if info is not None:
                flows[flow_key(info)].append(p)
        flow_list = list(flows.values())
        for triple, count in trackers.slowloris_candidates(flow_list):
            slowloris_activity[triple].append(window_time)
    print(path)
    print_activity("fragments", fragment_activity)
    print_activity("slowloris", slowloris_activity)
    print()

def main():
    if len(sys.argv) < 2:
        print("Usage: venv/bin/python diagnose_episodes.py capture1.pcap [capture2.pcap ...]")
        return
    for path in sys.argv[1:]:
        diagnose(path)

if __name__ == "__main__":
    main()