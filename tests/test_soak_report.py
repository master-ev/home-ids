from soak_report import rate_per_hour, session_hours, count_families, is_valid_session

TWO_HOURS_START = "2026-09-22T20:00:00"
TWO_HOURS_END = "2026-09-22T22:00:00"
EXPECTED_HOURS = 2.0
ALERT_COUNT = 6
EXPECTED_RATE = 3.0
SOME_PACKETS = 1000

def test_rate_per_hour_and_unknown_duration():
    assert rate_per_hour(ALERT_COUNT, EXPECTED_HOURS) == EXPECTED_RATE
    assert rate_per_hour(ALERT_COUNT, None) is None

def test_session_hours_uses_last_update_when_not_stopped_cleanly():
    session = {"start": TWO_HOURS_START, "last_update": TWO_HOURS_END, "end": None}
    assert session_hours(session) == EXPECTED_HOURS

def test_count_families_groups_detectors():
    alerts = [{"kind": "port_scan"}, {"kind": "slow_scan"}, {"kind": "slowloris"}]
    families = count_families(alerts)
    assert families["recon"] == 2
    assert families["flood"] == 1

def test_session_without_packets_is_invalid():
    empty = {"start": TWO_HOURS_START, "end": TWO_HOURS_END, "windows": 75, "packets": 0}
    assert is_valid_session(empty) is False
    assert is_valid_session(None) is False

def test_session_with_packets_is_valid():
    session = {"start": TWO_HOURS_START, "end": TWO_HOURS_END, "packets": SOME_PACKETS}
    assert is_valid_session(session) is True