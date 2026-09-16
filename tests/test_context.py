from scapy.all import IP, TCP
import context as ctx

BASE_TIME = 1000.0
ATTACKER = "192.168.1.50"
TARGET = "192.168.1.1"
FIRST_CLIENT_PORT = 40000
FLOOD_PORT = 8000
SCAN_PORT_COUNT = 10
FLOOD_FLOW_COUNT = 20
DECOY_SOURCES = ["10.0.0.1", "10.0.0.2", "10.0.0.3", ATTACKER]
SAME_PORT = 22

def make_flow(source, destination, source_port, destination_port, seconds_after_base):
    packet = IP(src=source, dst=destination) / TCP(sport=source_port, dport=destination_port, flags="S")
    packet.time = BASE_TIME + seconds_after_base
    return [packet]

def test_scan_has_one_flow_per_port():
    flow_list = []
    for index in range(SCAN_PORT_COUNT):
        flow_list.append(make_flow(ATTACKER, TARGET, FIRST_CLIENT_PORT, index + 1, 0))
    result = ctx.compute_context(flow_list)
    assert result[0]["ctx_src_ports"] == SCAN_PORT_COUNT
    assert result[0]["ctx_flows_per_port"] == 1.0

def test_flood_has_many_flows_on_one_port():
    flow_list = []
    for index in range(FLOOD_FLOW_COUNT):
        client_port = FIRST_CLIENT_PORT + index
        flow_list.append(make_flow(ATTACKER, TARGET, client_port, FLOOD_PORT, 0))
    result = ctx.compute_context(flow_list)
    assert result[0]["ctx_src_ports"] == 1
    assert result[0]["ctx_flows_per_port"] == FLOOD_FLOW_COUNT

def test_decoy_sources_are_counted_on_destination():
    flow_list = []
    for source in DECOY_SOURCES:
        flow_list.append(make_flow(source, TARGET, FIRST_CLIENT_PORT, SAME_PORT, 0))
    result = ctx.compute_context(flow_list)
    for context in result:
        assert context["ctx_dst_sources"] == len(DECOY_SOURCES)
        assert context["ctx_src_flows"] == 1

def test_different_windows_are_separate():
    flow_list = [make_flow(ATTACKER, TARGET, FIRST_CLIENT_PORT, SAME_PORT, 0), make_flow(ATTACKER, TARGET, FIRST_CLIENT_PORT, SAME_PORT, ctx.CONTEXT_WINDOW_SECONDS),]
    result = ctx.compute_context(flow_list)
    assert result[0]["ctx_src_flows"] == 1
    assert result[1]["ctx_src_flows"] == 1

def test_empty_input():
    assert ctx.compute_context([]) == []