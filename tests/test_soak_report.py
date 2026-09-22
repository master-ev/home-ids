from soak_report import rate_per_hour, session_hours, count_families

TWO_HOURS_START = "2026-09-22T20:00:00"
TWO_HOURS_END = "2026-09-22T22:00:00"
EXPECTED_HOURS = 2.0
ALERT_COUNT = 6
EXPECTED_RATE = 3.0

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