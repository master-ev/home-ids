import pytest
import live_ids
from live_ids import episode_starts, FRAGMENT_EPISODE_GAP_SECONDS
from flow_state import check_slow_scan, check_dest_scan, SLOW_SCAN_THRESHOLD, DEST_SCAN_THRESHOLD

START_TIME = 1000.0
STEP = 1.0
ONE_DAY = 86400.0
HALF_GAP = FRAGMENT_EPISODE_GAP_SECONDS / 2
FIRST_PORT = 1
SCANNER = "10.0.0.66"
TARGET = "192.168.1.1"
LONG_SCAN_FACTOR = 3

@pytest.fixture(autouse=True)
def clean_state():
    live_ids.reset_live_state()

def feed_slow_scan(port_count, start_time):
    results = []
    for index in range(port_count):
        port = FIRST_PORT + index
        now = start_time + index * STEP
        result = check_slow_scan(SCANNER, TARGET, port, now)
        if result is not None:
            results.append(result)
    return results

def feed_dest_scan(port_count, start_time):
    results = []
    for index in range(port_count):
        port = FIRST_PORT + index
        now = start_time + index * STEP
        result = check_dest_scan(TARGET, port, now)
        if result is not None:
            results.append(result)
    return results

def test_first_activity_starts_an_episode():
    never_seen = None
    assert episode_starts(never_seen, START_TIME, FRAGMENT_EPISODE_GAP_SECONDS) is True

def test_short_pause_continues_the_episode():
    now = START_TIME + HALF_GAP
    assert episode_starts(START_TIME, now, FRAGMENT_EPISODE_GAP_SECONDS) is False

def test_long_pause_starts_a_new_episode():
    now = START_TIME + FRAGMENT_EPISODE_GAP_SECONDS + STEP
    assert episode_starts(START_TIME, now, FRAGMENT_EPISODE_GAP_SECONDS) is True

def test_continuous_slow_scan_alerts_once():
    port_count = SLOW_SCAN_THRESHOLD * LONG_SCAN_FACTOR
    results = feed_slow_scan(port_count, START_TIME)
    assert len(results) == 1

def test_slow_scan_alerts_again_one_day_later():
    first = feed_slow_scan(SLOW_SCAN_THRESHOLD, START_TIME)
    second = feed_slow_scan(SLOW_SCAN_THRESHOLD, START_TIME + ONE_DAY)
    assert len(first) == 1
    assert len(second) == 1

def test_dest_scan_alerts_again_one_day_later():
    first = feed_dest_scan(DEST_SCAN_THRESHOLD, START_TIME)
    second = feed_dest_scan(DEST_SCAN_THRESHOLD, START_TIME + ONE_DAY)
    assert len(first) == 1
    assert len(second) == 1