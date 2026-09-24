import time
import pytest
import flow_state

SOURCE = "192.168.1.236"
TARGET = "192.168.1.1"
WINDOW_TIME = 1000.0

def setup_function(function):
    flow_state.reset_scan_state()

def test_slow_scan_alerts_at_the_threshold():
    result = None
    port = 0
    while port < flow_state.SLOW_SCAN_THRESHOLD:
        result = flow_state.check_slow_scan(SOURCE, TARGET, port, WINDOW_TIME)
        port = port + 1
    assert result == flow_state.SLOW_SCAN_THRESHOLD

def test_slow_scan_stays_silent_below_the_threshold():
    port = 0
    while port < flow_state.SLOW_SCAN_THRESHOLD - 1:
        result = flow_state.check_slow_scan(SOURCE, TARGET, port, WINDOW_TIME)
        assert result is None
        port = port + 1

def test_slow_scan_alerts_only_once():
    port = 0
    alerts = 0
    while port < flow_state.SLOW_SCAN_THRESHOLD * 3:
        result = flow_state.check_slow_scan(SOURCE, TARGET, port, WINDOW_TIME)
        if result is not None:
            alerts = alerts + 1
        port = port + 1
    assert alerts == 1

def test_repeated_port_does_not_count_twice():
    probe = 0
    while probe < flow_state.SLOW_SCAN_THRESHOLD * 2:
        result = flow_state.check_slow_scan(SOURCE, TARGET, 80, WINDOW_TIME)
        assert result is None
        probe = probe + 1

def test_old_entries_expire_out_of_the_window():
    port = 0
    while port < flow_state.SLOW_SCAN_THRESHOLD - 1:
        flow_state.check_slow_scan(SOURCE, TARGET, port, WINDOW_TIME)
        port = port + 1
    much_later = WINDOW_TIME + flow_state.SLOW_SCAN_WINDOW_SECONDS + 10
    result = flow_state.check_slow_scan(SOURCE, TARGET, 999, much_later)
    assert result is None

def test_dest_scan_counts_across_sources():
    result = None
    port = 0
    while port < flow_state.DEST_SCAN_THRESHOLD:
        result = flow_state.check_dest_scan(TARGET, port, WINDOW_TIME)
        port = port + 1
    assert result == flow_state.DEST_SCAN_THRESHOLD

def test_history_does_not_grow_without_bound():
    port = 0
    while port < 500:
        flow_state.check_slow_scan(SOURCE, TARGET, port, WINDOW_TIME)
        port = port + 1
    much_later = WINDOW_TIME + flow_state.SLOW_SCAN_WINDOW_SECONDS + 10
    flow_state.check_slow_scan(SOURCE, TARGET, 999, much_later)
    history = flow_state.slow_scan_history[(SOURCE, TARGET)]
    assert len(history) == 1

@pytest.mark.slow
def test_scan_state_scales_linearly():
    def time_for(flow_count):
        flow_state.reset_scan_state()
        started = time.perf_counter()
        port = 0
        while port < flow_count:
            flow_state.check_slow_scan(SOURCE, TARGET, port, WINDOW_TIME)
            port = port + 1
        return time.perf_counter() - started
    small_seconds = time_for(2000)
    large_seconds = time_for(4000)
    ratio = large_seconds / small_seconds
    assert ratio < 3.0

def test_port_counter_matches_the_history():
    probes = [(1000.0, 80), (1000.0, 80), (1000.0, 443), (1005.0, 22)]
    for window_time, port in probes:
        flow_state.check_slow_scan(SOURCE, TARGET, port, window_time)
    pair = (SOURCE, TARGET)
    history = flow_state.slow_scan_history[pair]
    port_counts = flow_state.slow_scan_port_counts[pair]
    ports_in_history = set()
    for entry_time, port in history:
        ports_in_history.add(port)
    assert set(port_counts.keys()) == ports_in_history
    assert len(port_counts) == len(ports_in_history)


def test_counter_is_emptied_when_everything_expires():
    port = 0
    while port < 50:
        flow_state.check_slow_scan(SOURCE, TARGET, port, WINDOW_TIME)
        port = port + 1
    much_later = WINDOW_TIME + flow_state.SLOW_SCAN_WINDOW_SECONDS + 10
    flow_state.check_slow_scan(SOURCE, TARGET, 999, much_later)
    pair = (SOURCE, TARGET)
    assert len(flow_state.slow_scan_history[pair]) == 1
    assert len(flow_state.slow_scan_port_counts[pair]) == 1

def test_latch_releases_when_the_window_empties():
    port = 0
    while port < flow_state.SLOW_SCAN_THRESHOLD:
        first_result = flow_state.check_slow_scan(SOURCE, TARGET, port, WINDOW_TIME)
        port = port + 1
    assert first_result == flow_state.SLOW_SCAN_THRESHOLD
    much_later = WINDOW_TIME + flow_state.SLOW_SCAN_WINDOW_SECONDS + 10
    second_result = None
    port = 0
    while port < flow_state.SLOW_SCAN_THRESHOLD:
        second_result = flow_state.check_slow_scan(SOURCE, TARGET, port, much_later + port)
        port = port + 1
    assert second_result == flow_state.SLOW_SCAN_THRESHOLD