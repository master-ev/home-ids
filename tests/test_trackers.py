from scapy.all import IP, TCP, ICMP, Ether
import trackers
from trackers import counts_as_scan_probe

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

from trackers import(classify_stealth_flags, detect_stealth_scans, TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG, STEALTH_MIN_PACKETS, STEALTH_MIN_PORTS,)
TCP_ECE = 0x40
TCP_CWR = 0x80
ATTACKER = "10.0.0.66"
VICTIM = "10.0.0.5"
FIRST_PORT = 20

def test_stealth_flag_types():
    assert classify_stealth_flags(0) == "NULL"
    assert classify_stealth_flags(TCP_FIN) == "FIN"
    assert classify_stealth_flags(TCP_FIN | TCP_PSH | TCP_URG) == "XMAS"
    assert classify_stealth_flags(TCP_SYN | TCP_FIN) == "SYN-FIN"

def test_normal_flags_are_not_stealth():
    normal_flag_values = [TCP_SYN, TCP_SYN | TCP_ACK, TCP_ACK, TCP_PSH | TCP_ACK, TCP_FIN | TCP_ACK, TCP_RST, TCP_RST | TCP_ACK,]
    for flags in normal_flag_values:
        assert classify_stealth_flags(flags) is None

def test_syn_with_ecn_is_not_stealth():
    syn_with_ecn = TCP_SYN | TCP_ECE | TCP_CWR
    assert classify_stealth_flags(syn_with_ecn) is None

def build_scan(flags, packet_count):
    packets = []
    for i in range(packet_count):
        port = FIRST_PORT + i
        packets.append((ATTACKER, VICTIM, port, flags))
    return packets

def test_xmas_scan_detected():
    xmas_flags = TCP_FIN | TCP_PSH | TCP_URG
    packets = build_scan(xmas_flags, STEALTH_MIN_PACKETS)
    alerts = detect_stealth_scans(packets)
    assert len(alerts) == 1
    assert alerts[0]["src"] == ATTACKER
    assert alerts[0]["scan_types"] == ["XMAS"]

def test_below_threshold_not_detected():
    too_few = STEALTH_MIN_PACKETS - 1
    packets = build_scan(0, too_few)
    alerts = detect_stealth_scans(packets)
    assert alerts == []

def test_same_port_repeated_not_detected():
    packets = []
    repeat_count = STEALTH_MIN_PACKETS * 2
    for i in range(repeat_count):
        packets.append((ATTACKER, VICTIM, FIRST_PORT, TCP_FIN))
    alerts = detect_stealth_scans(packets)
    assert alerts == []

def test_normal_teardown_traffic_not_detected():
    fin_ack = TCP_FIN | TCP_ACK
    packet_count = STEALTH_MIN_PACKETS * 10
    packets = build_scan(fin_ack, packet_count)
    alerts = detect_stealth_scans(packets)
    assert alerts == []

def test_sources_counted_separately():
    other_attacker = "10.0.0.77"
    packets = build_scan(0, STEALTH_MIN_PACKETS)
    few_packets = STEALTH_MIN_PORTS - 1
    for i in range(few_packets):
        port = FIRST_PORT + i
        packets.append((other_attacker, VICTIM, port, 0))
    alerts = detect_stealth_scans(packets)
    assert len(alerts) == 1
    assert alerts[0]["src"] == ATTACKER

def test_probes_count_for_scan_trackers():
    xmas_flags = TCP_FIN | TCP_PSH | TCP_URG
    probe_flags = [TCP_SYN, 0, TCP_FIN, xmas_flags]
    for flags in probe_flags:
        assert counts_as_scan_probe(flags) is True

def test_replies_and_mid_connection_do_not_count():
    reply_flags = [TCP_SYN | TCP_ACK, TCP_ACK, TCP_PSH | TCP_ACK, TCP_FIN | TCP_ACK, TCP_RST | TCP_ACK,]
    for flags in reply_flags:
        assert counts_as_scan_probe(flags) is False

def test_udp_flows_keep_counting():
    udp_has_no_tcp_flags = None
    assert counts_as_scan_probe(udp_has_no_tcp_flags) is True