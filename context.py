from scapy.all import IP, TCP, UDP

CONTEXT_WINDOW_SECONDS = 5
NO_PORT = 0
UNKNOWN_HOST = "unknown"
CONTEXT_FEATURES = ["ctx_src_flows", "ctx_src_ports", "ctx_src_dsts", "ctx_flows_per_port", "ctx_dst_sources", "ctx_reply_rate",]
NO_PORT_CTX = 0

def flow_got_reply(packets):
    first = packets[0]
    if not first.haslayer(IP):
        return False
    initiator_ip = first[IP].src
    initiator_port = NO_PORT_CTX
    if first.haslayer(TCP):
        initiator_port = first[TCP].sport
    elif first.haslayer(UDP):
        initiator_port = first[UDP].sport
    index = 0
    while index < len(packets):
        packet = packets[index]
        if packet.haslayer(IP):
            packet_port = NO_PORT_CTX
            if packet.haslayer(TCP):
                packet_port = packet[TCP].sport
            elif packet.haslayer(UDP):
                packet_port = packet[UDP].sport
            different_ip = packet[IP].src != initiator_ip
            different_port = packet_port != initiator_port
            if different_ip or different_port:
                return True
        index = index + 1
    return False

def flow_endpoints(packets):
    first_packet = packets[0]
    source = UNKNOWN_HOST
    destination = UNKNOWN_HOST
    port = NO_PORT
    if first_packet.haslayer(IP):
        source = first_packet[IP].src
        destination = first_packet[IP].dst
    if first_packet.haslayer(TCP):
        port = first_packet[TCP].dport
    elif first_packet.haslayer(UDP):
        port = first_packet[UDP].dport
    return source, destination, port

def find_start_time(flow_list):
    start_time = None
    for packets in flow_list:
        flow_time = float(packets[0].time)
        if start_time is None or flow_time < start_time:
            start_time = flow_time
    return start_time

def compute_context(flow_list):
    if len(flow_list) == 0:
        return []
    start_time = find_start_time(flow_list)
    described = []
    per_source = {}
    per_destination = {}
    for packets in flow_list:
        source, destination, port = flow_endpoints(packets)
        elapsed = float(packets[0].time) - start_time
        window = int(elapsed // CONTEXT_WINDOW_SECONDS)
        described.append((source, destination, window))
        source_key = (source, window)
        if source_key not in per_source:
            per_source[source_key] = {"flows": 0, "ports": set(), "destinations": set(), "replied": 0}
        source_stats = per_source[source_key]
        source_stats["flows"] = source_stats["flows"] + 1
        source_stats["ports"].add(port)
        source_stats["destinations"].add(destination)
        if flow_got_reply(packets):
            source_stats["replied"] = source_stats["replied"] + 1
        destination_key = (destination, window)
        if destination_key not in per_destination:
            per_destination[destination_key] = set()
        per_destination[destination_key].add(source)
    result = []
    for source, destination, window in described:
        source_stats = per_source[(source, window)]
        flow_count = source_stats["flows"]
        port_count = len(source_stats["ports"])
        flows_per_port = flow_count / port_count
        reply_rate = source_stats["replied"] / flow_count
        destination_sources = per_destination[(destination, window)]
        context = {"ctx_src_flows": flow_count, "ctx_src_ports": port_count, "ctx_src_dsts": len(source_stats["destinations"]), "ctx_flows_per_port": flows_per_port, "ctx_dst_sources": len(destination_sources), "ctx_reply_rate": reply_rate,}
        result.append(context)
    return result