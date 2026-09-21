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