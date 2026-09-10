from scapy.all import rdpcap, IP, IPv6, TCP, UDP
from collections import defaultdict

def get_ips_ports(packet):
    if IP in packet:
        source_ip, destination_ip = packet[IP].src, packet[IP].dst
    elif IPv6 in packet:
        source_ip, destination_ip = packet[IPv6].src, packet[IPv6].dst
    else:
        return None

    if TCP in packet:
        protocol, source_port, destination_port = "TCP", packet[TCP].sport, packet[TCP].dport
    elif UDP in packet:
        protocol, source_port, destination_port = "UDP", packet[UDP].sport, packet[UDP].dport
    else:
        return None
    return source_ip, destination_ip, source_port, destination_port, protocol

def flow_key(info):
    source_ip, destination_ip, source_port, destination_port, protocol = info
    a = (source_ip, source_port)
    b = (destination_ip, destination_port)
    if a <= b:
        return (a, b, protocol)
    else:
        return (b, a, protocol)

def compute_features(pkts):
    first = pkts[0]
    first_info = get_ips_ports(first)
    initiator_ip = first_info[0]
    fwd_packets = 0
    bwd_packets = 0
    fwd_bytes = 0
    bwd_bytes = 0
    for p in pkts:
        info = get_ips_ports(p)
        size = len(p)
        if info[0] == initiator_ip:
            fwd_packets += 1
            fwd_bytes += size
        else:
            bwd_packets += 1
            bwd_bytes += size

    total_packets = fwd_packets + bwd_packets
    total_bytes = fwd_bytes + bwd_bytes
    times = [p.time for p in pkts]
    duration = float(max(times) - min(times))
    average_packet_size = total_bytes / total_packets if total_packets > 0 else 0
    packets_per_sec = total_packets / duration if duration > 0 else 0
    fwd_bwd_ratio = fwd_bytes / bwd_bytes if bwd_bytes > 0 else 0
    destination_port = first_info[3]
    return {
        "destination_port": destination_port,
        "duration": round(duration, 3),
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "fwd_packets": fwd_packets,
        "bwd_packets": bwd_packets,
        "fwd_bytes": fwd_bytes,
        "bwd_bytes": bwd_bytes,
        "average_packet_size": round(average_packet_size, 1),
        "packets_per_sec": round(packets_per_sec, 1),
        "fwd_bwd_ratio": round(fwd_bwd_ratio, 2),
    }

packets = rdpcap("capture.pcap")
flows = defaultdict(list)
for packet in packets:
    info = get_ips_ports(packet)
    if info is not None:
        flows[flow_key(info)].append(packet)

print(f"{len(flows)} flows\n")
for key, pkts in flows.items():
    feats = compute_features(pkts)
    print(f"Flow to port {feats['destination_port']}:")
    for name, value in feats.items():
        print(f"    {name:18} {value}")
    print()
