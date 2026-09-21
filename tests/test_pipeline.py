import json
import os
import pytest
from scapy.all import rdpcap
import live_ids
from incidents import load_alerts, compute_severity, SEVERITY_MEDIUM

STEALTH_CAPTURE = "stealth_sX.pcap"
FRAGMENT_CAPTURE = "frag_scan.pcap"
NORMAL_CAPTURE = "normal.pcap"
REQUIRED_MODEL_FILES = ["my_model.joblib", "my_model_v2.joblib", "normal.pcap"]
STEALTH_SOURCE = "192.168.1.236"

def require_capture(path):
    if not os.path.exists(path):
        pytest.skip("capture not available: " + path)

def split_into_windows(packets, window_seconds):
    windows = []
    if len(packets) == 0:
        return windows
    current = []
    window_start = float(packets[0].time)
    for pkt in packets:
        pkt_time = float(pkt.time)
        elapsed = pkt_time - window_start
        if elapsed >= window_seconds:
            windows.append(current)
            current = []
            window_start = pkt_time
        current.append(pkt)
    if len(current) > 0:
        windows.append(current)
    return windows

def replay_capture(path):
    packets = rdpcap(path)
    windows = split_into_windows(packets, live_ids.WINDOW_SECONDS)
    for window in windows:
        live_ids.analyze_window(window)

def read_logged_alerts(log_path):
    alerts = []
    if not os.path.exists(log_path):
        return alerts
    with open(log_path) as f:
        for line in f:
            stripped = line.strip()
            if stripped == "":
                continue
            alerts.append(json.loads(stripped))
    return alerts

def alerts_of_kind(alerts, kind):
    matching = []
    for alert in alerts:
        if alert["kind"] == kind:
            matching.append(alert)
    return matching

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