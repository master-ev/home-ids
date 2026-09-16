from scapy.all import IP, TCP
from features import compute_rich_features

BASE_TIME = 1000.0
STEP = 0.01
LOCAL_IP = "127.0.0.1"
CLIENT_IP = "192.168.1.50"
SERVER_IP = "192.168.1.1"
CLIENT_PORT = 40000
SERVER_PORT = 8000

def make_packet(source, destination, source_port, destination_port, flags, seconds):
    packet = IP(src=source, dst=destination) / TCP(sport=source_port, dport=destination_port, flags=flags)
    packet.time = BASE_TIME + seconds
    return packet

def handshake(client_ip, server_ip):
    flow = [make_packet(client_ip, server_ip, CLIENT_PORT, SERVER_PORT, "S", 0), make_packet(server_ip, client_ip, SERVER_PORT, CLIENT_PORT, "SA", STEP), make_packet(client_ip, server_ip, CLIENT_PORT, SERVER_PORT, "A", 2 * STEP),]
    return flow

def test_same_ip_reply_is_backward():
    features = compute_rich_features(handshake(LOCAL_IP, LOCAL_IP))
    assert features["total_fwd_packets"] == 2
    assert features["total_bwd_packets"] == 1

def test_different_ips_still_work():
    features = compute_rich_features(handshake(CLIENT_IP, SERVER_IP))
    assert features["total_fwd_packets"] == 2
    assert features["total_bwd_packets"] == 1

def test_single_syn_has_no_backward():
    flow = [make_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, "S", 0)]
    features = compute_rich_features(flow)
    assert features["total_bwd_packets"] == 0
    assert features["duration"] == 0