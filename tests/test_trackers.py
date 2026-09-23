from scapy.all import IP, TCP, ICMP, Ether
import trackers
from trackers import counts_as_scan_probe, is_lone_ack_probe, detect_ack_scans, ACK_SCAN_MIN_PORTS, held_open_connections, persistent_connections, SLOWLORIS_MIN_PERSISTENT
from live_ids import slowloris_triple

FROM_SCANNER = True
FROM_TARGET = False
EMPTY = 0
SOME_DATA = 100
ATTACKER = "192.168.1.244"
TARGET = "192.168.1.1"
SERVER_PORT = 80
CLIENT_PORT = 46000
SERVER_TRIPLE = ("10.0.0.5", "192.168.1.1", 80)
FEW_PACKETS = 4
MANY_PACKETS = 50
CLIENT_IP = "192.168.1.244"
SERVER_IP = "192.168.1.1"
SERVER_PORT = 80
CLIENT_PORT = 51234
TCP_PROTO = "TCP"

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

def test_lone_ack_is_a_probe_with_or_without_rst_reply():
    no_reply = [(FROM_SCANNER, TCP_ACK, EMPTY)]
    rst_reply = [(FROM_SCANNER, TCP_ACK, EMPTY), (FROM_TARGET, TCP_RST, EMPTY)]
    assert is_lone_ack_probe(no_reply) is True
    assert is_lone_ack_probe(rst_reply) is True

def test_mid_connection_slices_are_not_probes():
    ack_then_data = [(FROM_SCANNER, TCP_ACK, EMPTY), (FROM_TARGET, TCP_PSH | TCP_ACK, SOME_DATA)]
    ack_then_ack = [(FROM_SCANNER, TCP_ACK, EMPTY), (FROM_TARGET, TCP_ACK, EMPTY)]
    data_first = [(FROM_SCANNER, TCP_PSH | TCP_ACK, SOME_DATA)]
    syn_first = [(FROM_SCANNER, TCP_SYN, EMPTY)]
    assert is_lone_ack_probe(ack_then_data) is False
    assert is_lone_ack_probe(ack_then_ack) is False
    assert is_lone_ack_probe(data_first) is False
    assert is_lone_ack_probe(syn_first) is False

def build_ack_probes(port_count, is_probe):
    flows = []
    for index in range(port_count):
        port = FIRST_PORT + index
        flows.append((ATTACKER, VICTIM, port, is_probe))
    return flows

def test_ack_scan_detected():
    flows = build_ack_probes(ACK_SCAN_MIN_PORTS, True)
    alerts = detect_ack_scans(flows)
    assert len(alerts) == 1
    assert alerts[0]["src"] == ATTACKER

def test_ack_probes_below_threshold_are_silent():
    flows = build_ack_probes(ACK_SCAN_MIN_PORTS - 1, True)
    assert detect_ack_scans(flows) == []

def test_many_ports_without_lone_probes_are_silent():
    flows = build_ack_probes(ACK_SCAN_MIN_PORTS * 3, False)
    assert detect_ack_scans(flows) == []

def test_same_port_repeated_is_not_ack_scan():
    flows = []
    repeat_count = ACK_SCAN_MIN_PORTS * 2
    for index in range(repeat_count):
        flows.append((ATTACKER, VICTIM, FIRST_PORT, True))
    assert detect_ack_scans(flows) == []

def summary(conn, packets=FEW_PACKETS, initiator_ack=True, closed=False):
    return {"triple": SERVER_TRIPLE, "conn": conn, "packets": packets, "initiator_ack": initiator_ack, "closed": closed}

def test_half_open_connections_are_not_held_open():
    summaries = [summary("c1", initiator_ack=False), summary("c2", initiator_ack=False)]
    assert held_open_connections(summaries) == {}

def test_closed_connections_are_not_held_open():
    summaries = [summary("c1", closed=True), summary("c2", closed=True)]
    assert held_open_connections(summaries) == {}

def test_chatty_connections_are_not_held_open():
    summaries = [summary("c1", packets=MANY_PACKETS)]
    assert held_open_connections(summaries) == {}

def test_quiet_established_connections_are_held_open():
    summaries = [summary("c1"), summary("c2")]
    held = held_open_connections(summaries)
    assert held[SERVER_TRIPLE] == {"c1", "c2"}

def test_persistent_connections_are_the_shared_ones():
    current = {"c1", "c2", "c3"}
    previous = {"c2", "c3", "c9"}
    assert persistent_connections(current, previous) == {"c2", "c3"}

def test_new_connections_every_window_are_not_persistent():
    current = {"n1", "n2", "n3"}
    previous = {"o1", "o2", "o3"}
    assert persistent_connections(current, previous) == set()

def test_triple_is_the_same_in_both_directions():
    outgoing = (CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, TCP_PROTO)
    incoming = (SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, TCP_PROTO)
    assert slowloris_triple(outgoing) == slowloris_triple(incoming)
    assert slowloris_triple(outgoing)[2] == SERVER_PORT

PRIVILEGED_SOURCE_PORT = 53
HIGH_TARGET_PORT = 8080

def test_triple_picks_the_lower_port_even_when_it_is_the_source():
    spoofed = ("192.168.1.236", "192.168.1.1", PRIVILEGED_SOURCE_PORT, HIGH_TARGET_PORT, TCP_PROTO)
    assert slowloris_triple(spoofed)[2] == PRIVILEGED_SOURCE_PORT