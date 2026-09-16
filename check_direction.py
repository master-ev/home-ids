import sys
from collections import defaultdict
from scapy.all import IP, TCP, UDP, rdpcap
from features import compute_rich_features, flow_key, get_ips_ports

NO_PORT = 0
BACKWARD_FEATURE = "total_bwd_packets"

def endpoint(packet):
    ip = packet[IP].src
    port = NO_PORT
    if packet.haslayer(TCP):
        port = packet[TCP].sport
    elif packet.haslayer(UDP):
        port = packet[UDP].sport
    return (ip, port)


def check_capture(path):
    packets = rdpcap(path)
    flows = defaultdict(list)
    for packet in packets:
        info = get_ips_ports(packet)
        if info is not None:
            flows[flow_key(info)].append(packet)
    real_replies = 0
    counted_backward = 0
    same_ip_flows = 0
    for flow_packets in flows.values():
        first_packet = flow_packets[0]
        if not first_packet.haslayer(IP):
            continue
        initiator = endpoint(first_packet)
        for packet in flow_packets:
            if packet.haslayer(IP) and endpoint(packet) != initiator:
                real_replies = real_replies + 1
        features = compute_rich_features(flow_packets)
        counted_backward = counted_backward + int(features.get(BACKWARD_FEATURE, 0))
        if first_packet[IP].src == first_packet[IP].dst:
            same_ip_flows = same_ip_flows + 1
    print(f"{path:<18} flows={len(flows):<6} real_replies={real_replies:<7} "f"counted_by_features={counted_backward:<7} same_ip_flows={same_ip_flows}")

def main():
    if len(sys.argv) < 2:
        print("Usage: venv/bin/python check_direction.py file1.pcap [file2.pcap ...]")
        return
    for path in sys.argv[1:]:
        check_capture(path)

if __name__ == "__main__":
    main()