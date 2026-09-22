from collections import Counter
from metrics_report import wrong_kinds

ACK_SCAN_WINDOWS = 2
SYN_FLOOD_ALERTS = 4

def test_generic_recon_trackers_are_acceptable_on_scans():
    logged = Counter({"port_scan": 2, "slow_scan": 1, "distributed_scan": 1})
    assert wrong_kinds(logged, "port_scan") == Counter()

def test_udp_label_on_ack_scan_is_wrong():
    logged = Counter({"ack_scan": ACK_SCAN_WINDOWS, "udp_scan": ACK_SCAN_WINDOWS})
    assert wrong_kinds(logged, "ack_scan") == Counter({"udp_scan": ACK_SCAN_WINDOWS})

def test_slowloris_on_syn_flood_is_wrong():
    logged = Counter({"syn_flood": SYN_FLOOD_ALERTS, "slowloris": 1})
    assert wrong_kinds(logged, "syn_flood") == Counter({"slowloris": 1})