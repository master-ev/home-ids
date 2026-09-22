from soak_replay import build_session
from soak_report import session_hours

START_TIMESTAMP = 1_700_000_000.0
TWO_HOURS_SECONDS = 7200.0
EXPECTED_HOURS = 2.0
WINDOWS = 1440
PACKETS = 50000

def test_replay_session_is_readable_by_soak_report():
    end_timestamp = START_TIMESTAMP + TWO_HOURS_SECONDS
    session = build_session(START_TIMESTAMP, end_timestamp, WINDOWS, PACKETS, "test.pcapng")
    assert session_hours(session) == EXPECTED_HOURS
    assert session["packets"] == PACKETS