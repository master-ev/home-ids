import sys
from collections import defaultdict
from scapy.all import rdpcap
import live_ids
from features import get_ips_ports, flow_key
from replay import split_into_windows

def max_probe_ports(path):
    packets = rdpcap(path)
    windows = split_into_windows(packets, live_ids.WINDOW_SECONDS)
    total_probes = 0
    best = 0
    best_source = "-"
    for window in windows:
        flows = defaultdict(list)
        for p in window:
            info = get_ips_ports(p)
            if info is not None:
                flows[flow_key(info)].append(p)
        ports_by_source = defaultdict(set)
        for key in flows:
            probe = live_ids.flow_ack_probe(flows[key])
            if probe is None:
                continue
            src, dst, dport, is_probe = probe
            if is_probe:
                total_probes = total_probes + 1
                ports_by_source[src].add(dport)
        for src in ports_by_source:
            count = len(ports_by_source[src])
            if count > best:
                best = count
                best_source = src
    return total_probes, best, best_source

def main():
    if len(sys.argv) < 2:
        print("Usage: venv/bin/python check_ack_scan.py capture1.pcap [capture2.pcap ...]")
        return
    for path in sys.argv[1:]:
        total_probes, best, best_source = max_probe_ports(path)
        print(f"{path:<24} lone ACK probe flows={total_probes:<5} max ports per source/window={best:<4} ({best_source})")

if __name__ == "__main__":
    main()