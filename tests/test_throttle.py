import pytest
import live_ids
from live_ids import cooldown_allows, emit_alert, ALERT_COOLDOWN_SECONDS
from replay import read_logged_alerts

START_TIME = 1000.0
HALF_COOLDOWN = ALERT_COOLDOWN_SECONDS / 2
SMALL_STEP = 1.0
ATTACKER = "10.0.0.66"
OTHER_ATTACKER = "10.0.0.77"
VICTIM = "192.168.1.1"

@pytest.fixture
def throttle_log(tmp_path, monkeypatch):
    live_ids.reset_live_state()
    log_path = tmp_path / "alerts.jsonl"
    monkeypatch.setattr(live_ids, "ALERT_LOG", str(log_path))
    return str(log_path)

def make_alert(kind, source):
    return {"timestamp": "t", "kind": kind, "description": kind, "source": source, "destination": VICTIM, "num_flows": 1, "num_ports": 1, "model_verdict": kind, "confidence": None}

def count_notified(alerts):
    notified = 0
    for alert in alerts:
        if alert["notified"]:
            notified = notified + 1
    return notified

def test_first_alert_is_always_allowed():
    no_previous_notice = None
    assert cooldown_allows(no_previous_notice, START_TIME, ALERT_COOLDOWN_SECONDS) is True

def test_within_cooldown_is_blocked():
    now = START_TIME + HALF_COOLDOWN
    assert cooldown_allows(START_TIME, now, ALERT_COOLDOWN_SECONDS) is False

def test_after_cooldown_is_allowed_again():
    now = START_TIME + ALERT_COOLDOWN_SECONDS
    assert cooldown_allows(START_TIME, now, ALERT_COOLDOWN_SECONDS) is True

def test_repeats_are_logged_but_notified_once(throttle_log):
    repeat_count = 3
    for index in range(repeat_count):
        now = START_TIME + index * SMALL_STEP
        emit_alert(make_alert("port_scan", ATTACKER), "test", now)
    alerts = read_logged_alerts(throttle_log)
    assert len(alerts) == repeat_count
    assert count_notified(alerts) == 1


def test_next_notice_reports_suppressed_repeats(throttle_log):
    emit_alert(make_alert("port_scan", ATTACKER), "test", START_TIME)
    emit_alert(make_alert("port_scan", ATTACKER), "test", START_TIME + SMALL_STEP)
    emit_alert(make_alert("port_scan", ATTACKER), "test", START_TIME + 2 * SMALL_STEP)
    after_cooldown = START_TIME + ALERT_COOLDOWN_SECONDS
    emit_alert(make_alert("port_scan", ATTACKER), "test", after_cooldown)
    alerts = read_logged_alerts(throttle_log)
    last = alerts[-1]
    assert last["notified"] is True
    assert last["suppressed_repeats"] == 2

def test_new_kind_or_new_source_is_notified_immediately(throttle_log):
    emit_alert(make_alert("port_scan", ATTACKER), "test", START_TIME)
    emit_alert(make_alert("brute_force", ATTACKER), "test", START_TIME + SMALL_STEP)
    emit_alert(make_alert("port_scan", OTHER_ATTACKER), "test", START_TIME + SMALL_STEP)
    alerts = read_logged_alerts(throttle_log)
    assert count_notified(alerts) == 3

from live_ids import family_of

UNMAPPED_KIND_A = "future_tracker_a"
UNMAPPED_KIND_B = "future_tracker_b"


def test_family_of_known_kinds_and_fail_safe_for_unknown():
    assert family_of("port_scan") == "recon"
    assert family_of("slow_scan") == "recon"
    assert family_of("stealth_scan") == "evasion"
    assert family_of(UNMAPPED_KIND_A) == UNMAPPED_KIND_A


def test_same_family_detectors_notified_once(throttle_log):
    emit_alert(make_alert("slow_scan", ATTACKER), "test", START_TIME)
    emit_alert(make_alert("port_scan", ATTACKER), "test", START_TIME + SMALL_STEP)
    alerts = read_logged_alerts(throttle_log)
    assert len(alerts) == 2
    assert count_notified(alerts) == 1


def test_evasion_after_recon_is_notified(throttle_log):
    emit_alert(make_alert("slow_scan", ATTACKER), "test", START_TIME)
    emit_alert(make_alert("stealth_scan", ATTACKER), "test", START_TIME + SMALL_STEP)
    alerts = read_logged_alerts(throttle_log)
    assert count_notified(alerts) == 2


def test_recon_after_evasion_is_covered(throttle_log):
    emit_alert(make_alert("stealth_scan", ATTACKER), "test", START_TIME)
    emit_alert(make_alert("slow_scan", ATTACKER), "test", START_TIME + SMALL_STEP)
    alerts = read_logged_alerts(throttle_log)
    assert count_notified(alerts) == 1


def test_flood_after_recon_is_notified(throttle_log):
    emit_alert(make_alert("port_scan", ATTACKER), "test", START_TIME)
    emit_alert(make_alert("dos", ATTACKER), "test", START_TIME + SMALL_STEP)
    alerts = read_logged_alerts(throttle_log)
    assert count_notified(alerts) == 2


def test_unknown_kinds_never_merge(throttle_log):
    emit_alert(make_alert(UNMAPPED_KIND_A, ATTACKER), "test", START_TIME)
    emit_alert(make_alert(UNMAPPED_KIND_B, ATTACKER), "test", START_TIME + SMALL_STEP)
    alerts = read_logged_alerts(throttle_log)
    assert count_notified(alerts) == 2


def test_next_notice_lists_silent_detectors(throttle_log):
    emit_alert(make_alert("slow_scan", ATTACKER), "test", START_TIME)
    emit_alert(make_alert("port_scan", ATTACKER), "test", START_TIME + SMALL_STEP)
    emit_alert(make_alert("port_scan", ATTACKER), "test", START_TIME + 2 * SMALL_STEP)
    after_cooldown = START_TIME + ALERT_COOLDOWN_SECONDS
    emit_alert(make_alert("slow_scan", ATTACKER), "test", after_cooldown)
    alerts = read_logged_alerts(throttle_log)
    last = alerts[-1]
    assert last["notified"] is True
    assert last["suppressed_repeats"] == 2
    assert last["suppressed_kinds"] == {"port_scan": 2}