import json
import os
import pytest
from scapy.all import rdpcap
import live_ids
from incidents import load_alerts, compute_severity, SEVERITY_MEDIUM
from replay import split_into_windows, read_logged_alerts, replay_to_log

STEALTH_CAPTURE = "stealth_sX.pcap"
FRAGMENT_CAPTURE = "frag_scan.pcap"
NORMAL_CAPTURE = "normal.pcap"
REQUIRED_MODEL_FILES = ["my_model.joblib", "my_model_v2.joblib", "normal.pcap"]
STEALTH_SOURCE = "192.168.1.236"
DNS_CAPTURES = ["normal_dns2.pcap", "dns_div2.pcap", "dns_div3.pcap", "dns_normal.pcap"]
DECOY_CAPTURE = "decoy.pcap"
SLOWLORIS_CAPTURE = "slowloris1.pcap"
CONNECT_SCAN_CAPTURE = "scan_connect_router.pcap"

def require_capture(path):
    if not os.path.exists(path):
        pytest.skip("capture not available: " + path)

def replay_capture(path):
    packets = rdpcap(path)
    windows = split_into_windows(packets, live_ids.WINDOW_SECONDS)
    for window in windows:
        live_ids.analyze_window(window)

def alerts_of_kind(alerts, kind):
    matching = []
    for alert in alerts:
        if alert["kind"] == kind:
            matching.append(alert)
    return matching

def test_decoy_replay_labelled_port_scan_not_suspicious(alert_log):
    require_capture(DECOY_CAPTURE)
    replay_capture(DECOY_CAPTURE)
    alerts = read_logged_alerts(alert_log)
    scans = alerts_of_kind(alerts, "port_scan")
    vague = alerts_of_kind(alerts, "suspicious")
    assert len(scans) >= 1
    assert vague == []

@pytest.fixture(scope="module")
def models_loaded():
    for path in REQUIRED_MODEL_FILES:
        if not os.path.exists(path):
            pytest.skip("model file not available: " + path)
    live_ids.load_models()
    return True

@pytest.fixture
def alert_log(tmp_path, monkeypatch, models_loaded):
    live_ids.reset_live_state()
    log_path = tmp_path / "alerts.jsonl"
    monkeypatch.setattr(live_ids, "ALERT_LOG", str(log_path))
    return str(log_path)

def test_stealth_replay_logs_stealth_alert(alert_log):
    require_capture(STEALTH_CAPTURE)
    replay_capture(STEALTH_CAPTURE)
    alerts = read_logged_alerts(alert_log)
    stealth = alerts_of_kind(alerts, "stealth_scan")
    assert len(stealth) >= 1
    assert stealth[0]["source"] == STEALTH_SOURCE
    assert "XMAS" in stealth[0]["description"]

def test_stealth_replay_suppresses_udp_scan_label(alert_log):
    require_capture(STEALTH_CAPTURE)
    replay_capture(STEALTH_CAPTURE)
    alerts = read_logged_alerts(alert_log)
    wrong_labels = alerts_of_kind(alerts, "udp_scan")
    assert wrong_labels == []

def test_fragment_replay_logs_fragment_alert(alert_log):
    require_capture(FRAGMENT_CAPTURE)
    replay_capture(FRAGMENT_CAPTURE)
    alerts = read_logged_alerts(alert_log)
    fragments = alerts_of_kind(alerts, "fragmented_scan")
    assert len(fragments) >= 1

def test_normal_replay_logs_no_evasion_alerts(alert_log):
    require_capture(NORMAL_CAPTURE)
    replay_capture(NORMAL_CAPTURE)
    alerts = read_logged_alerts(alert_log)
    stealth = alerts_of_kind(alerts, "stealth_scan")
    fragments = alerts_of_kind(alerts, "fragmented_scan")
    assert stealth == []
    assert fragments == []

def test_logged_stealth_alert_gets_medium_severity(alert_log):
    require_capture(STEALTH_CAPTURE)
    replay_capture(STEALTH_CAPTURE)
    loaded = load_alerts(alert_log)
    stealth_types = []
    for alert in loaded:
        if alert["type"] == "stealth_scan":
            stealth_types.append(alert["type"])
    assert len(stealth_types) >= 1
    severity = compute_severity(stealth_types[0], len(stealth_types))
    assert severity == SEVERITY_MEDIUM

def test_replay_to_log_restores_alert_log(models_loaded, tmp_path):
    require_capture(STEALTH_CAPTURE)
    original_log = live_ids.ALERT_LOG
    log_path = str(tmp_path / "metrics_alerts.jsonl")
    alerts = replay_to_log(STEALTH_CAPTURE, log_path)
    assert live_ids.ALERT_LOG == original_log
    assert len(alerts) >= 1

@pytest.mark.parametrize("capture", DNS_CAPTURES)
def test_dns_replay_never_labelled_brute_force(alert_log, capture):
    require_capture(capture)
    replay_capture(capture)
    alerts = read_logged_alerts(alert_log)
    brute = alerts_of_kind(alerts, "brute_force")
    assert brute == []    

def test_slowloris_replay_raises_no_scan_tracker_alerts(alert_log):
    require_capture(SLOWLORIS_CAPTURE)
    replay_capture(SLOWLORIS_CAPTURE)
    alerts = read_logged_alerts(alert_log)
    assert alerts_of_kind(alerts, "slow_scan") == []
    assert alerts_of_kind(alerts, "distributed_scan") == []
    assert len(alerts_of_kind(alerts, "slowloris")) >= 1


def test_connect_scan_replay_still_raises_slow_scan(alert_log):
    require_capture(CONNECT_SCAN_CAPTURE)
    replay_capture(CONNECT_SCAN_CAPTURE)
    alerts = read_logged_alerts(alert_log)
    assert len(alerts_of_kind(alerts, "slow_scan")) >= 1


def test_stealth_replay_still_raises_slow_scan(alert_log):
    require_capture(STEALTH_CAPTURE)
    replay_capture(STEALTH_CAPTURE)
    alerts = read_logged_alerts(alert_log)
    assert len(alerts_of_kind(alerts, "slow_scan")) >= 1

def alert_keys(alerts, only_notified):
    keys = set()
    for alert in alerts:
        if only_notified and not alert.get("notified", True):
            continue
        keys.add((alert["source"], alert["destination"], alert["kind"]))
    return keys

def test_decoy_replay_notifies_every_key_but_fewer_alerts(alert_log):
    require_capture(DECOY_CAPTURE)
    replay_capture(DECOY_CAPTURE)
    alerts = read_logged_alerts(alert_log)
    logged_keys = alert_keys(alerts, False)
    notified_keys = alert_keys(alerts, True)
    notified_count = 0
    for alert in alerts:
        if alert["notified"]:
            notified_count = notified_count + 1
    assert notified_keys == logged_keys
    assert notified_count < len(alerts)

SCANNER = "192.168.1.236"
ROUTER = "192.168.1.1"
SLOWLORIS_REPEAT_CAPTURE = "slowloris_test.pcap"

def first_packet_time(path):
    packets = rdpcap(path, count=1)
    return float(packets[0].time)

def replay_in_time_order(paths):
    ordered = sorted(paths, key=first_packet_time)
    for path in ordered:
        replay_capture(path)

def count_alerts(alerts, kind, source, destination):
    count = 0
    for alert in alerts:
        if alert["kind"] != kind:
            continue
        if source is not None and alert["source"] != source:
            continue
        if alert["destination"] != destination:
            continue
        count = count + 1
    return count

def test_same_scanner_days_apart_raises_scan_trackers_twice(alert_log):
    require_capture(CONNECT_SCAN_CAPTURE)
    require_capture(STEALTH_CAPTURE)
    replay_in_time_order([CONNECT_SCAN_CAPTURE, STEALTH_CAPTURE])
    alerts = read_logged_alerts(alert_log)
    assert count_alerts(alerts, "slow_scan", SCANNER, ROUTER) == 2
    assert count_alerts(alerts, "distributed_scan", None, ROUTER) == 2

def test_same_slowloris_pair_two_captures_alerts_twice(alert_log):
    require_capture(SLOWLORIS_CAPTURE)
    require_capture(SLOWLORIS_REPEAT_CAPTURE)
    replay_in_time_order([SLOWLORIS_CAPTURE, SLOWLORIS_REPEAT_CAPTURE])
    alerts = read_logged_alerts(alert_log)
    slowloris = alerts_of_kind(alerts, "slowloris")
    assert len(slowloris) == 2