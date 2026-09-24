from scapy.all import ICMP, IP, IPv6, TCP, UDP
from features import ICMP_NO_PORT

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
    ip_layer = pkt.getlayer(IP)
    if ip_layer is not None:
        src = ip_layer.src
        dst = ip_layer.dst
        ipv4_layer = ip_layer
    else:
        ipv6_layer = pkt.getlayer(IPv6)
        if ipv6_layer is None:
            return None
        src = ipv6_layer.src
        dst = ipv6_layer.dst
        ipv4_layer = None
    sport = None
    dport = None
    flags = None
    payload_length = None
    proto = None
    tcp_layer = pkt.getlayer(TCP)
    if tcp_layer is not None:
        sport = tcp_layer.sport
        dport = tcp_layer.dport
        flags = int(tcp_layer.flags)
        proto = TCP_PROTO
        if ipv4_layer is not None:
            ip_header_bytes = ipv4_layer.ihl * HEADER_WORD_BYTES
            tcp_header_bytes = tcp_layer.dataofs * HEADER_WORD_BYTES
            payload_length = ipv4_layer.len - ip_header_bytes - tcp_header_bytes
        else:
            tcp_header_bytes = tcp_layer.dataofs * HEADER_WORD_BYTES
            payload_length = ipv6_layer.plen - tcp_header_bytes
    else:
        udp_layer = pkt.getlayer(UDP)
        if udp_layer is not None:
            sport = udp_layer.sport
            dport = udp_layer.dport
            proto = UDP_PROTO
        else:
            icmp_layer = pkt.getlayer(ICMP)
            if icmp_layer is not None:
                sport = ICMP_NO_PORT
                dport = ICMP_NO_PORT
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