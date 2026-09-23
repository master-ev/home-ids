from labels import(choose_campaign_label, ANOMALY_VERDICT, SUSPICIOUS_MIN_FLOWS, MIN_ATTACK_FLOWS, FEW_PORTS_MAX, DOS_VERDICT, SCAN_MIN_PORTS, SCAN_VERDICT)

DOS_PCAP_FLOWS = 1448
INFLATED_PORT_COUNT = 8
DECOY_FLOWS_PER_WINDOW = 11
SINGLE_PORT = 1
UDP_SCAN_PORTS = 6
RETRANSMIT_PORTS = 4
RETRANSMIT_FLOWS = 10

def test_anomaly_only_campaign_is_labelled_anomaly():
    flows = MIN_ATTACK_FLOWS + 1
    kind, desc = choose_campaign_label(ANOMALY_VERDICT, flows, SINGLE_PORT)
    assert kind == "anomaly"

def test_small_anomaly_campaign_is_ignored():
    flows = SUSPICIOUS_MIN_FLOWS - 1
    kind, desc = choose_campaign_label(ANOMALY_VERDICT, flows, SINGLE_PORT)
    assert kind is None

def test_real_bruteforce_still_labelled_brute_force():
    flows = MIN_ATTACK_FLOWS + 1
    kind, desc = choose_campaign_label("bruteforce", flows, FEW_PORTS_MAX)
    assert kind == "brute_force"

def test_udp_scan_label_unchanged():
    kind, desc = choose_campaign_label("udp_scan", SUSPICIOUS_MIN_FLOWS, UDP_SCAN_PORTS)
    assert kind == "udp_scan"

def test_dos_verdict_with_inflated_ports_is_dos():
    kind, desc = choose_campaign_label(DOS_VERDICT, DOS_PCAP_FLOWS, INFLATED_PORT_COUNT)
    assert kind == "dos"


def test_dos_verdict_with_scan_shape_is_not_dos():
    flows = SCAN_MIN_PORTS * 2
    ports = flows
    kind, desc = choose_campaign_label(DOS_VERDICT, flows, ports)
    assert kind != "dos"
    assert kind == "port_scan"


def test_scan_verdict_few_ports_one_flow_each_is_port_scan():
    ports = SCAN_MIN_PORTS - 1
    kind, desc = choose_campaign_label(SCAN_VERDICT, DECOY_FLOWS_PER_WINDOW, ports)
    assert kind == "port_scan"


def test_scan_verdict_repeated_port_is_not_port_scan():
    flows = MIN_ATTACK_FLOWS + 1
    kind, desc = choose_campaign_label(SCAN_VERDICT, flows, SINGLE_PORT)
    assert kind != "port_scan"

def test_scan_with_retransmissions_is_still_port_scan():
    kind, desc = choose_campaign_label(SCAN_VERDICT, RETRANSMIT_FLOWS, RETRANSMIT_PORTS)
    assert kind == "port_scan"