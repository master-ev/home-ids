from scapy.all import IP, TCP, UDP

ICMP_FLOOD_THRESHOLD = 100
FRAGMENT_FLOOD_THRESHOLD = 30
SLOWLORIS_MIN_CONNECTIONS = 20
SLOWLORIS_MAX_PKTS_PER_CONN = 12
SLOWLORIS_MIN_WINDOWS = 3
ICMP_PROTO = "ICMP"
MORE_FRAGMENTS_FLAG = 1
NO_FRAGMENT_OFFSET = 0

def is_fragment(packet):
    if IP not in packet:
        return False
    more_fragments = int(packet[IP].flags) & MORE_FRAGMENTS_FLAG
    has_offset = packet[IP].frag != NO_FRAGMENT_OFFSET
    return bool(more_fragments) or has_offset

def count_fragments_per_pair(packets):
    counts = {}
    index = 0
    while index < len(packets):
        packet = packets[index]
        if is_fragment(packet):
            pair = (packet[IP].src, packet[IP].dst)
            if pair not in counts:
                counts[pair] = 0
            counts[pair] = counts[pair] + 1
        index = index + 1
    return counts

def fragment_alerts(packets):
    counts = count_fragments_per_pair(packets)
    alerts = []
    for pair, count in counts.items():
        if count >= FRAGMENT_FLOOD_THRESHOLD:
            alerts.append((pair[0], pair[1], count))
    return alerts

def count_icmp_per_pair(packets):
    counts = {}
    index = 0
    while index < len(packets):
        packet = packets[index]
        if IP in packet and packet.haslayer("ICMP"):
            pair = (packet[IP].src, packet[IP].dst)
            if pair not in counts:
                counts[pair] = 0
            counts[pair] = counts[pair] + 1
        index = index + 1
    return counts

def icmp_flood_alerts(packets):
    counts = count_icmp_per_pair(packets)
    alerts = []
    for pair, count in counts.items():
        if count >= ICMP_FLOOD_THRESHOLD:
            alerts.append((pair[0], pair[1], count))
    return alerts

def server_port(source_port, destination_port):
    if source_port < destination_port:
        return source_port
    return destination_port

def count_slow_connections(flow_list):
    counts = {}
    index = 0
    while index < len(flow_list):
        packets = flow_list[index]
        index = index + 1
        first = packets[0]
        if IP not in first or TCP not in first:
            continue
        if len(packets) > SLOWLORIS_MAX_PKTS_PER_CONN:
            continue
        src = first[IP].src
        dst = first[IP].dst
        sport = first[TCP].sport
        dport = first[TCP].dport
        port = server_port(sport, dport)
        host_a = min(src, dst)
        host_b = max(src, dst)
        triple = (host_a, host_b, port)
        if triple not in counts:
            counts[triple] = 0
        counts[triple] = counts[triple] + 1
    return counts

def slowloris_candidates(flow_list):
    counts = count_slow_connections(flow_list)
    candidates = []
    for triple, count in counts.items():
        if count >= SLOWLORIS_MIN_CONNECTIONS:
            candidates.append((triple, count))
    return candidates