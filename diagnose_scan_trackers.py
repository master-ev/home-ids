import sys
from collections import defaultdict
from scapy.all import rdpcap, TCP
from features import get_ips_ports, flow_key
from replay import split_into_windows
from trackers import TCP_ACK
import live_ids

EPHEMERAL_PORT_MIN = 32768
SLOW_SCAN_THRESHOLD = live_ids.SLOW_SCAN_THRESHOLD
DEST_SCAN_THRESHOLD = live_ids.DEST_SCAN_THRESHOLD

def max_distinct(ports_by_key):
    best = 0
    for key in ports_by_key:
        count = len(ports_by_key[key])
        if count > best:
            best = count
    return best

def fires_text(value, threshold):
    if value >= threshold:
        return "FIRES"
    return "silent"

def diagnose(path):
    packets = rdpcap(path)
    windows = split_into_windows(packets, live_ids.WINDOW_SECONDS)
    ack_first = 0
    ack_first_ephemeral = 0
    probe_first = 0
    probe_first_ephemeral = 0
    udp_flows = 0
    old_pair_ports = defaultdict(set)
    old_dest_ports = defaultdict(set)
    new_pair_ports = defaultdict(set)
    new_dest_ports = defaultdict(set)
    for window in windows:
        flows = defaultdict(list)
        for p in window:
            info = get_ips_ports(p)
            if info is not None:
                flows[flow_key(info)].append(p)
        for key in flows:
            pkts = flows[key]
            first = pkts[0]
            src, dst, sport, dport, proto = get_ips_ports(first)
            if proto == live_ids.ICMP_PROTO:
                continue
            is_ephemeral = dport is not None and dport >= EPHEMERAL_PORT_MIN
            old_pair_ports[(src, dst)].add(dport)
            old_dest_ports[dst].add(dport)
            is_probe = True
            if TCP in first:
                flags = int(first[TCP].flags)
                has_ack = (flags & TCP_ACK) != 0
                if has_ack:
                    is_probe = False
                    ack_first = ack_first + 1
                    if is_ephemeral:
                        ack_first_ephemeral = ack_first_ephemeral + 1
                else:
                    probe_first = probe_first + 1
                    if is_ephemeral:
                        probe_first_ephemeral = probe_first_ephemeral + 1
            else:
                udp_flows = udp_flows + 1
            if is_probe:
                new_pair_ports[(src, dst)].add(dport)
                new_dest_ports[dst].add(dport)
    old_pair = max_distinct(old_pair_ports)
    new_pair = max_distinct(new_pair_ports)
    old_dest = max_distinct(old_dest_ports)
    new_dest = max_distinct(new_dest_ports)
    print(path)
    print(f"  TCP flows starting WITH ack   : {ack_first}  (ephemeral dport: {ack_first_ephemeral})")
    print(f"  TCP flows starting WITHOUT ack: {probe_first}  (ephemeral dport: {probe_first_ephemeral})")
    print(f"  UDP flows (unchanged rule)    : {udp_flows}")
    print(f"  slow_scan  max ports per pair : old {old_pair} ({fires_text(old_pair, SLOW_SCAN_THRESHOLD)})" f"  ->  new {new_pair} ({fires_text(new_pair, SLOW_SCAN_THRESHOLD)})")
    print(f"  dest_scan  max ports per dst  : old {old_dest} ({fires_text(old_dest, DEST_SCAN_THRESHOLD)})" f"  ->  new {new_dest} ({fires_text(new_dest, DEST_SCAN_THRESHOLD)})")
    print()

def main():
    if len(sys.argv) < 2:
        print("Usage: venv/bin/python diagnose_scan_trackers.py capture1.pcap [capture2.pcap ...]")
        return
    for path in sys.argv[1:]:
        diagnose(path)

if __name__ == "__main__":
    main()