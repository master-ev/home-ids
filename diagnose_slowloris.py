import sys
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP
import live_ids
import trackers
from features import get_ips_ports, flow_key
from replay import split_into_windows

NAME_WIDTH = 22

def connection_facts(pkts):
    first = pkts[0]
    initiator = first[IP].src
    initiator_ack = False
    closed = False
    for pkt in pkts:
        if not (IP in pkt and TCP in pkt):
            continue
        flags = int(pkt[TCP].flags)
        base_flags = flags & trackers.TCP_BASE_FLAGS_MASK
        from_initiator = pkt[IP].src == initiator
        has_ack = (base_flags & trackers.TCP_ACK) != 0
        if from_initiator and has_ack:
            initiator_ack = True
        is_fin = (base_flags & trackers.TCP_FIN) != 0
        is_rst = (base_flags & trackers.TCP_RST) != 0
        if is_fin or is_rst:
            closed = True
    return len(pkts), initiator_ack, closed

def triple_of(info):
    src, dst, sport, dport, proto = info
    hosts = sorted([src, dst])
    port = min(sport, dport)
    return (hosts[0], hosts[1], port)

def diagnose(path):
    packets = rdpcap(path)
    windows = split_into_windows(packets, live_ids.WINDOW_SECONDS)
    previous = defaultdict(set)
    print(path)
    window_index = 0
    for window in windows:
        window_index = window_index + 1
        flows = defaultdict(list)
        for p in window:
            info = get_ips_ports(p)
            if info is not None:
                flows[flow_key(info)].append(p)
        stats = defaultdict(lambda: {"total": 0, "established": 0, "open": 0, "conns": set()})
        for key in flows:
            pkts = flows[key]
            first = pkts[0]
            if not (IP in first and TCP in first):
                continue
            info = get_ips_ports(first)
            triple = triple_of(info)
            packet_count, initiator_ack, closed = connection_facts(pkts)
            if packet_count > trackers.SLOWLORIS_MAX_PKTS_PER_CONN:
                continue
            entry = stats[triple]
            entry["total"] = entry["total"] + 1
            if initiator_ack:
                entry["established"] = entry["established"] + 1
                if not closed:
                    entry["open"] = entry["open"] + 1
                    entry["conns"].add(key)
        for triple in sorted(stats):
            entry = stats[triple]
            if entry["total"] < trackers.SLOWLORIS_MIN_CONNECTIONS:
                continue
            persistent = entry["conns"] & previous[triple]
            label = triple[0] + " <-> " + triple[1] + ":" + str(triple[2])
            print(f"  w{window_index:<3} {label:<40} candidates={entry['total']:<5}" f" established={entry['established']:<5} open={entry['open']:<5}" f" persistent={len(persistent)}")
            previous[triple] = entry["conns"]
        for triple in stats:
            if triple not in previous:
                previous[triple] = stats[triple]["conns"]
    print()

def main():
    if len(sys.argv) < 2:
        print("Usage: venv/bin/python diagnose_slowloris.py capture1.pcap [...]")
        return
    for path in sys.argv[1:]:
        diagnose(path)

if __name__ == "__main__":
    main()