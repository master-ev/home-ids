from live_ids import(choose_campaign_label, ANOMALY_VERDICT, SUSPICIOUS_MIN_FLOWS, MIN_ATTACK_FLOWS, FEW_PORTS_MAX,)

SINGLE_PORT = 1
UDP_SCAN_PORTS = 6

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