from scapy.all import IP, TCP, UDP, ICMP

HEADER_WORD_BYTES = 4
TCP_PROTO = "TCP"
UDP_PROTO = "UDP"
ICMP_PROTO = "ICMP"
VIEW_SRC = 0
VIEW_DST = 1
VIEW_SPORT = 2
VIEW_DPORT = 3
VIEW_FLAGS = 4
VIEW_PAYLOAD = 5
VIEW_PROTO = 6

def tcp_payload_length(pkt):
    ip_header_bytes = pkt[IP].ihl * HEADER_WORD_BYTES
    tcp_header_bytes = pkt[TCP].dataofs * HEADER_WORD_BYTES
    payload_length = pkt[IP].len - ip_header_bytes - tcp_header_bytes
    return payload_length

def build_view(pkt):
    if IP not in pkt:
        return None
    ip_layer = pkt[IP]
    src = ip_layer.src
    dst = ip_layer.dst
    sport = None
    dport = None
    flags = None
    payload_length = None
    proto = None
    if TCP in pkt:
        tcp_layer = pkt[TCP]
        sport = tcp_layer.sport
        dport = tcp_layer.dport
        flags = int(tcp_layer.flags)
        payload_length = tcp_payload_length(pkt)
        proto = TCP_PROTO
    elif UDP in pkt:
        udp_layer = pkt[UDP]
        sport = udp_layer.sport
        dport = udp_layer.dport
        proto = UDP_PROTO
    elif ICMP in pkt:
        proto = ICMP_PROTO
    view = (src, dst, sport, dport, flags, payload_length, proto)
    return view

def build_views(packets):
    views = []
    for pkt in packets:
        views.append(build_view(pkt))
    return views

def is_tcp(view):
    if view is None:
        return False
    if not isinstance(view, tuple):
        raise TypeError("expected a packet view tuple, got " + type(view).__name__)
    return view[VIEW_PROTO] == TCP_PROTO

def tcp_views(views):
    selected = []
    for view in views:
        if is_tcp(view):
            selected.append(view)
    return selected