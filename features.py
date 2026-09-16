import statistics
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

# def compute_features(pkts):
#     first = pkts[0]
#     first_info = get_ips_ports(first)
#     initiator_ip = first_info[0]
#     fwd_packets = 0
#     bwd_packets = 0
#     fwd_bytes = 0
#     bwd_bytes = 0
#     for p in pkts:
#         info = get_ips_ports(p)
#         size = len(p)
#         if info[0] == initiator_ip:
#             fwd_packets += 1
#             fwd_bytes += size
#         else:
#             bwd_packets += 1
#             bwd_bytes += size

#     total_packets = fwd_packets + bwd_packets
#     total_bytes = fwd_bytes + bwd_bytes
#     times = [p.time for p in pkts]
#     duration = float(max(times) - min(times))
#     average_packet_size = total_bytes / total_packets if total_packets > 0 else 0
#     packets_per_sec = total_packets / duration if duration > 0 else 0
#     fwd_bwd_ratio = fwd_bytes / bwd_bytes if bwd_bytes > 0 else 0
#     destination_port = first_info[3]
#     return {
#         "destination_port": destination_port,
#         "duration": round(duration, 3),
#         "total_packets": total_packets,
#         "total_bytes": total_bytes,
#         "fwd_packets": fwd_packets,
#         "bwd_packets": bwd_packets,
#         "fwd_bytes": fwd_bytes,
#         "bwd_bytes": bwd_bytes,
#         "average_packet_size": round(average_packet_size, 1),
#         "packets_per_sec": round(packets_per_sec, 1),
#         "fwd_bwd_ratio": round(fwd_bwd_ratio, 2),
#     }

# packets = rdpcap("capture.pcap")
# flows = defaultdict(list)
# for packet in packets:
#     info = get_ips_ports(packet)
#     if info is not None:
#         flows[flow_key(info)].append(packet)

# print(f"{len(flows)} flows\n")
# for key, pkts in flows.items():
#     feats = compute_features(pkts)
#     print(f"Flow to port {feats['destination_port']}:")
#     for name, value in feats.items():
#         print(f"    {name:18} {value}")
#     print()

def compute_rich_features(pkts):
    first_info = get_ips_ports(pkts[0])
    initiator_ip = first_info[0]
    initiator_port = first_info[2]
    fwd_sizes = []
    bwd_sizes = []
    times = []
    syn_count = 0
    rst_count = 0
    ack_count = 0
    psh_count = 0
    fin_count = 0
    for p in pkts:
        info = get_ips_ports(p)
        size = len(p)
        times.append(float(p.time))
        if TCP in p:
            flags = str(p[TCP].flags)
            if "S" in flags:
                syn_count += 1
            if "R" in flags:
                rst_count += 1
            if "A" in flags:
                ack_count += 1
            if "P" in flags:
                psh_count += 1
            if "F" in flags:
                fin_count += 1
        is_forward = info[0] == initiator_ip and info[2] == initiator_ip
        if is_forward:
            fwd_sizes.append(size)
        else:
            bwd_sizes.append(size)
    all_sizes = fwd_sizes + bwd_sizes
    times.sort()
    iats = [times[i+1] - times[i] for i in range(len(times) - 1)]

    def safe_stat(values, func):
        if len(values) < 1:
            return 0
        if func == statistics.stdev and len(values) < 2:
            return 0
        return func(values)
    duration = max(times) - min(times) if len(times) > 1 else 0
    return {
        "total_fwd_packets": len(fwd_sizes),
        "total_bwd_packets": len(bwd_sizes),
        "fwd_bytes": sum(fwd_sizes),
        "bwd_bytes": sum(bwd_sizes),
        "fwd_pkt_len_max": max(fwd_sizes) if fwd_sizes else 0,
        "fwd_pkt_len_min": min(fwd_sizes) if fwd_sizes else 0,
        "fwd_pkt_len_mean": safe_stat(fwd_sizes, statistics.mean),
        "fwd_pkt_len_std": safe_stat(fwd_sizes, statistics.stdev),
        "bwd_pkt_len_max": max(bwd_sizes) if bwd_sizes else 0,
        "bwd_pkt_len_mean": safe_stat(bwd_sizes, statistics.mean),
        "pkt_len_mean": safe_stat(all_sizes, statistics.mean),
        "pkt_len_std": safe_stat(all_sizes, statistics.stdev),
        "flow_iat_mean": safe_stat(iats, statistics.mean),
        "flow_iat_std": safe_stat(iats, statistics.stdev),
        "flow_iat_max": max(iats) if iats else 0,
        "flow_iat_min": min(iats) if iats else 0,
        "duration": round(duration, 4),
        "flow_bytes_per_sec": sum(all_sizes) / duration if duration > 0 else 0,
        "flow_packets_per_sec": len(all_sizes) / duration if duration > 0 else 0,
        "syn_count": syn_count,
        "rst_count": rst_count,
        "ack_count": ack_count,
        "psh_count": psh_count,
        "fin_count": fin_count,
    }

if __name__ == "__main__":
    from scapy.all import rdpcap
    from collections import defaultdict
    packets = rdpcap("capture.pcap")
    flows = defaultdict(list)
    for packet in packets:
        info = get_ips_ports(packet)
        if info is not None:
            flows[flow_key(info)].append(packet)
    for key, pkts in list(flows.items())[:3]:
        feats = compute_rich_features(pkts)
        print(f"Flow to port {get_ips_ports(pkts[0])[3]}:")
        for name, value in feats.items():
            print(f"    {name:22} {value}")
        print()