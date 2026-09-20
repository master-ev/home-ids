from scapy.all import IP, TCP, ICMP, Ether
import trackers

ATTACKER = "192.168.1.244"
TARGET = "192.168.1.1"
SERVER_PORT = 80
CLIENT_PORT = 46000

def build(packet):
    return Ether(bytes(packet))

def make_tcp(src, dst, sport, dport, flags="S"):
    return build(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags))

def make_icmp(src, dst):
    return build(Ether() / IP(src=src, dst=dst) / ICMP())

def make_fragment(src, dst, frag_offset, more):
    packet = IP(src=src, dst=dst) / ("A" * 16)
    packet.frag = frag_offset
    if more:
        packet.flags = "MF"
    return build(Ether() / packet)

def test_fragment_detected():
    frag = make_fragment(ATTACKER, TARGET, 0, True)
    assert trackers.is_fragment(frag) is True

def test_normal_packet_not_fragment():
    normal = make_tcp(ATTACKER, TARGET, CLIENT_PORT, SERVER_PORT)
    assert trackers.is_fragment(normal) is False

def test_fragment_threshold():
    below = trackers.FRAGMENT_FLOOD_THRESHOLD - 1
    packets = []
    index = 0
    while index < below:
        packets.append(make_fragment(ATTACKER, TARGET, index + 1, True))
        index = index + 1
    assert len(trackers.fragment_alerts(packets)) == 0
    packets.append(make_fragment(ATTACKER, TARGET, below + 1, True))
    alerts = trackers.fragment_alerts(packets)
    assert len(alerts) == 1
    assert alerts[0][2] == trackers.FRAGMENT_FLOOD_THRESHOLD

def test_icmp_counted_per_pair():
    packets = []
    index = 0
    while index < trackers.ICMP_FLOOD_THRESHOLD:
        packets.append(make_icmp(ATTACKER, TARGET))
        index = index + 1
    alerts = trackers.icmp_flood_alerts(packets)
    assert len(alerts) == 1
    assert alerts[0][0] == ATTACKER
    assert alerts[0][2] == trackers.ICMP_FLOOD_THRESHOLD

def test_icmp_below_threshold_silent():
    packets = [make_icmp(ATTACKER, TARGET)]
    assert len(trackers.icmp_flood_alerts(packets)) == 0

def test_slowloris_server_port_stable_regardless_of_direction():
    flow_list = []
    index = 0
    while index < trackers.SLOWLORIS_MIN_CONNECTIONS:
        client_port = CLIENT_PORT + index
        reply = make_tcp(TARGET, ATTACKER, SERVER_PORT, client_port, flags="SA")
        flow_list.append([reply])
        index = index + 1
    candidates = trackers.slowloris_candidates(flow_list)
    assert len(candidates) == 1
    triple, count = candidates[0]
    assert triple[2] == SERVER_PORT
    assert count == trackers.SLOWLORIS_MIN_CONNECTIONS

def test_slowloris_high_traffic_connections_ignored():
    flow_list = []
    index = 0
    while index < trackers.SLOWLORIS_MIN_CONNECTIONS:
        client_port = CLIENT_PORT + index
        packets = []
        packet_index = 0
        while packet_index <= trackers.SLOWLORIS_MAX_PKTS_PER_CONN:
            packets.append(make_tcp(ATTACKER, TARGET, client_port, SERVER_PORT))
            packet_index = packet_index + 1
        flow_list.append(packets)
        index = index + 1
    assert len(trackers.slowloris_candidates(flow_list)) == 0

def test_slowloris_below_min_connections_silent():
    flow_list = []
    index = 0
    while index < trackers.SLOWLORIS_MIN_CONNECTIONS - 1:
        flow_list.append([make_tcp(ATTACKER, TARGET, CLIENT_PORT + index, SERVER_PORT)])
        index = index + 1
    assert len(trackers.slowloris_candidates(flow_list)) == 0