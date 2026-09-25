import trackers

SRC = "192.168.1.236"
DST = "192.168.1.1"
SYN = 0x02
ACK = 0x10

def make_view(src, dst, flags, payload):
    return (src, dst, 4444, 80, flags, payload, "TCP")

def half_open_flow(payload):
    return [make_view(SRC, DST, SYN, payload)]

def complete_flow():
    return [make_view(SRC, DST, SYN, 0), make_view(SRC, DST, ACK, 0)]

def build_flows(count, flow_factory):
    flows = {}
    index = 0
    while index < count:
        key = ("flow", index)
        flows[key] = flow_factory()
        index = index + 1
    return flows

def test_many_half_open_is_a_flood():
    flows = build_flows(trackers.SYN_FLOOD_MIN_HALF_OPEN, lambda: half_open_flow(0))
    alerts = trackers.syn_flood_alerts(flows)
    assert len(alerts) == 1
    src, dst, count = alerts[0]
    assert count == trackers.SYN_FLOOD_MIN_HALF_OPEN

def test_payload_does_not_hide_the_flood():
    flows = build_flows(trackers.SYN_FLOOD_MIN_HALF_OPEN, lambda: half_open_flow(500))
    alerts = trackers.syn_flood_alerts(flows)
    assert len(alerts) == 1

def test_completed_handshakes_are_not_a_flood():
    flows = build_flows(trackers.SYN_FLOOD_MIN_HALF_OPEN * 2, complete_flow)
    alerts = trackers.syn_flood_alerts(flows)
    assert alerts == []

def test_below_threshold_is_silent():
    flows = build_flows(trackers.SYN_FLOOD_MIN_HALF_OPEN - 1, lambda: half_open_flow(0))
    alerts = trackers.syn_flood_alerts(flows)
    assert alerts == []

def test_half_open_flag_check_ignores_payload_size():
    bare = trackers.is_syn_without_ack(half_open_flow(0))
    padded = trackers.is_syn_without_ack(half_open_flow(500))
    assert bare is True
    assert padded is True

def test_a_flow_with_ack_is_not_half_open():
    assert trackers.is_syn_without_ack(complete_flow()) is False

def make_view_port(src, dst, dport, flags):
    return (src, dst, 4444, dport, flags, 0, "TCP")

def half_open_on_port(dport):
    return [make_view_port(SRC, DST, dport, SYN)]

def test_scan_across_many_ports_is_not_a_flood():
    flows = {}
    port = 0
    while port < 100:
        flows[("flow", port)] = half_open_on_port(port)
        port = port + 1
    alerts = trackers.syn_flood_alerts(flows)
    assert alerts == []

def test_flood_on_one_port_still_fires():
    flows = {}
    index = 0
    while index < trackers.SYN_FLOOD_MIN_HALF_OPEN + 5:
        flows[("flow", index)] = half_open_on_port(80)
        index = index + 1
    alerts = trackers.syn_flood_alerts(flows)
    assert len(alerts) == 1