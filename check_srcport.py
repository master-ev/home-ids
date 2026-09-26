import sys
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP
import live_ids
from features import get_ips_ports, flow_key
from replay import split_into_windows

PRIVILEGED_PORT_MAX = 1024
SAMPLE_SIZE = 8

def real_probe_ports(window):
    ports = set()
    for pkt in window:
        if not (IP in pkt and TCP in pkt):
            continue
        flags = int(pkt[TCP].flags)
        has_ack = (flags & trackers_ack()) != 0
        if has_ack:
            continue
        ports.add(pkt[TCP].dport)
    return ports

def trackers_ack():
    import trackers
    return trackers.TCP_ACK

def diagnose(path):
    packets = rdpcap(path)
    windows = split_into_windows(packets, live_ids.WINDOW_SECONDS)
    pipeline_ports = defaultdict(set)
    probe_ports = set()
    low_source_ports = 0
    tcp_flows = 0
    samples = []
    for window in windows:
        probe_ports.update(real_probe_ports(window))
        flows = defaultdict(list)
        for p in window:
            info = get_ips_ports(p)
            if info is not None:
                flows[flow_key(info)].append(p)
        for key in flows:
            pkts = flows[key]
            info = get_ips_ports(pkts[0])
            src, dst, sport, dport, proto = info
            if proto != "TCP":
                continue
            tcp_flows = tcp_flows + 1
            if sport < PRIVILEGED_PORT_MAX:
                low_source_ports = low_source_ports + 1
            pipeline_ports[(src, dst)].add(dport)
            if len(samples) < SAMPLE_SIZE:
                samples.append(f"{src}:{sport} -> {dst}:{dport}")
    best_pair = 0
    for pair in pipeline_ports:
        count = len(pipeline_ports[pair])
        if count > best_pair:
            best_pair = count
    print(path)
    print(f"  TCP flows: {tcp_flows}   flows with source port < 1024: {low_source_ports}")
    print(f"  Ports actually probed (no-ACK packets): {len(probe_ports)}")
    print(f"  Max distinct dports the trackers see per (src,dst): {best_pair}")
    print("  Sample flows as the pipeline sees them:")
    for sample in samples:
        print(sample)
    print()

def main():
    if len(sys.argv) < 2:
        print("Usage: venv/bin/python check_srcport.py capture1.pcap [...]")
        return
    for path in sys.argv[1:]:
        diagnose(path)

if __name__ == "__main__":
    main()