from scapy.all import rdpcap, IP, IPv6, TCP, UDP
from collections import defaultdict

def flow_key(packet):
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
    elif IPv6 in packet:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst
    else:
        return None
    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
    else:
        return None

    endpoint_a = (source_ip, source_port)
    endpoint_b = (destination_ip, destination_port)
    if endpoint_a <= endpoint_b:
        return (endpoint_a, endpoint_b, protocol)
    else:
        return (endpoint_b, endpoint_a, protocol)

packets = rdpcap("capture.pcap")

flows = defaultdict(list)
for packet in packets:
    key = flow_key(packet)
    if key is not None:
        flows[key].append(packet)

print(f"Grouped {len(packets)} packets into {len(flows)} flows\n")

for key, pkts in flows.items():
    endpoint_a, endpoint_b, protocol = key
    packet_count = len(pkts)
    total_bytes = sum(len(p) for p in pkts)
    times = [p.time for p in pkts]
    duration = max(times) - min(times)
    a_str = f"{endpoint_a[0]}:{endpoint_a[1]}"
    b_str = f"{endpoint_b[0]}:{endpoint_b[1]}"
    print(f"{protocol} {a_str} <-> {b_str}")
    print(f"    {packet_count} packets, {total_bytes} bytes, {duration:.2f}s")
