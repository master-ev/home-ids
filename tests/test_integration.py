import os
from collections import defaultdict
import pytest
from scapy.all import rdpcap
MODEL = "my_model_v2.joblib"
SCAN_CAPTURE = "scan.pcap"
FRAG_CAPTURE = "frag_scan.pcap"

pytestmark = pytest.mark.skipif(
    not os.path.exists(MODEL),
    reason="trained model not present (fresh clone) - unit tests cover the logic")

def run_capture(path, window_seconds=5):
    import live_ids
    live_ids.load_models()
    collected = []
    original_log = live_ids.log_alert
    live_ids.log_alert = lambda alert: collected.append(alert)
    try:
        packets = rdpcap(path)
        start = float(packets[0].time)
        windows = defaultdict(list)
        for packet in packets:
            index = int((float(packet.time) - start) // window_seconds)
            windows[index].append(packet)
        for index in sorted(windows.keys()):
            live_ids.analyze_window(windows[index])
    finally:
        live_ids.log_alert = original_log
    return collected

def kinds(alerts):
    result = set()
    index = 0
    while index < len(alerts):
        result.add(alerts[index]["kind"])
        index = index + 1
    return result

@pytest.mark.skipif(not os.path.exists(SCAN_CAPTURE), reason="scan.pcap not present")
def test_scan_capture_raises_scan_alert():
    alerts = run_capture(SCAN_CAPTURE)
    assert len(alerts) > 0
    assert "port_scan" in kinds(alerts) or "slow_scan" in kinds(alerts)

@pytest.mark.skipif(not os.path.exists(FRAG_CAPTURE), reason="frag_scan.pcap not present")
def test_fragmented_scan_is_detected():
    alerts = run_capture(FRAG_CAPTURE)
    assert "fragmented_scan" in kinds(alerts)