import incidents as inc
from incidents import SEVERITY_HIGH
BASE_TIME = 1000000.0
ROUTER = "192.168.1.1"
SERVER = "192.168.1.20"
ATTACKER = "192.168.1.50"
DECOY_SOURCES = ["10.0.0.1", "10.0.0.2", "10.0.0.3", ATTACKER]
SHORT_INTERVAL = 10
SERIES_LENGTH = 4
EPOCH_EXAMPLE = 1000
REAL_ALERT_LINE = ('{"timestamp": "2026-09-15T04:51:12.603311", "kind": "port_scan", ''"description": "PORT SCAN(500 ports)", "source": "192.168.1.236", ''"destination": "192.168.1.1", "num_flows": 502, "num_ports": 500, ''"model_verdict": "scan"}')
CONF_HIGH = 0.9
CONF_LOW = 0.4
CONF_A = 0.8
CONF_B = 0.6
CONF_AVERAGE = 0.7


def make_alert(src, attack_type, seconds_after_base, dst):
    alert = {"src": src, "dst": dst, "type": attack_type, "time": BASE_TIME + seconds_after_base, "raw": {},}
    return alert

def make_series(src, attack_type, count, interval, start, dst):
    alerts = []
    index = 0
    while index < count:
        offset = start + index * interval
        alerts.append(make_alert(src, attack_type, offset, dst))
        index = index + 1
    return alerts

def test_close_alerts_form_one_incident():
    alerts = make_series(ATTACKER, "port_scan", SERIES_LENGTH, SHORT_INTERVAL, 0, ROUTER)
    incident_list = inc.build_incidents(alerts)
    assert len(incident_list) == 1
    assert incident_list[0]["alert_count"] == SERIES_LENGTH

def test_gap_exactly_at_limit_keeps_one_incident():
    alerts = [make_alert(ATTACKER, "port_scan", 0, ROUTER), make_alert(ATTACKER, "port_scan", inc.INCIDENT_GAP_SECONDS, ROUTER),]
    incident_list = inc.build_incidents(alerts)
    assert len(incident_list) == 1

def test_gap_over_limit_splits_incident():
    over_limit = inc.INCIDENT_GAP_SECONDS + 1
    alerts = [make_alert(ATTACKER, "port_scan", 0, ROUTER), make_alert(ATTACKER, "port_scan", over_limit, ROUTER),]
    incident_list = inc.build_incidents(alerts)
    assert len(incident_list) == 2

def test_slow_scan_uses_longer_gap():
    over_normal_limit = inc.INCIDENT_GAP_SECONDS + 1
    alerts = [make_alert(ATTACKER, "slow_scan", 0, ROUTER), make_alert(ATTACKER, "slow_scan", over_normal_limit, ROUTER),]
    incident_list = inc.build_incidents(alerts)
    assert len(incident_list) == 1

def test_dos_is_always_high():
    assert inc.compute_severity("dos", 1) == inc.SEVERITY_HIGH

def test_bruteforce_threshold():
    below = inc.BRUTEFORCE_HIGH_MIN_ALERTS - 1
    exact = inc.BRUTEFORCE_HIGH_MIN_ALERTS
    assert inc.compute_severity("brute_force", below) == inc.SEVERITY_MEDIUM
    assert inc.compute_severity("brute_force", exact) == inc.SEVERITY_HIGH

def test_scan_threshold():
    below = inc.SCAN_MEDIUM_MIN_ALERTS - 1
    exact = inc.SCAN_MEDIUM_MIN_ALERTS
    assert inc.compute_severity("port_scan", below) == inc.SEVERITY_LOW
    assert inc.compute_severity("port_scan", exact) == inc.SEVERITY_MEDIUM

def test_decoys_merge_into_one_campaign():
    alerts = []
    index = 0
    while index < len(DECOY_SOURCES):
        alerts.append(make_alert(DECOY_SOURCES[index], "port_scan", 0, SERVER))
        index = index + 1
    incident_list = inc.build_incidents(alerts)
    campaign_list = inc.build_campaigns(incident_list)
    assert len(incident_list) == len(DECOY_SOURCES)
    assert len(campaign_list) == 1
    assert campaign_list[0]["pattern"] == inc.PATTERN_MULTI_SOURCE
    assert campaign_list[0]["severity"] == inc.SEVERITY_MEDIUM

def test_scan_then_bruteforce_is_high():
    alerts = [make_alert(ATTACKER, "port_scan", 0, SERVER), make_alert(ATTACKER, "brute_force", SHORT_INTERVAL, SERVER),]
    incident_list = inc.build_incidents(alerts)
    campaign_list = inc.build_campaigns(incident_list)
    assert len(campaign_list) == 1
    assert campaign_list[0]["pattern"] == inc.PATTERN_MULTI_STAGE
    assert campaign_list[0]["severity"] == inc.SEVERITY_HIGH

def test_far_apart_incidents_stay_separate():
    too_late = inc.CAMPAIGN_GAP_SECONDS + 1
    alerts = [make_alert(ATTACKER, "port_scan", 0, SERVER), make_alert(ATTACKER, "brute_force", too_late, SERVER),]
    incident_list = inc.build_incidents(alerts)
    campaign_list = inc.build_campaigns(incident_list)
    assert len(campaign_list) == 2

def test_placeholder_values_do_not_link():
    alerts = [make_alert(inc.MULTIPLE_VALUE, "distributed_scan", 0, ROUTER), make_alert(inc.MULTIPLE_VALUE, "anomaly", 0, SERVER),]
    incident_list = inc.build_incidents(alerts)
    campaign_list = inc.build_campaigns(incident_list)
    assert len(campaign_list) == 2

def test_parse_time_formats():
    assert inc.parse_time(EPOCH_EXAMPLE) == float(EPOCH_EXAMPLE)
    assert inc.parse_time(str(EPOCH_EXAMPLE)) == float(EPOCH_EXAMPLE)
    with_z = inc.parse_time("2026-09-15T10:00:00Z")
    with_offset = inc.parse_time("2026-09-15T10:00:00+00:00")
    assert with_z == with_offset
    assert inc.parse_time("not a time") == inc.NO_TIME
    assert inc.parse_time(None) == inc.NO_TIME

def test_load_alerts_reads_real_format(tmp_path):
    alerts_file = tmp_path / "alerts.jsonl"
    alerts_file.write_text(REAL_ALERT_LINE + "\n")
    alerts = inc.load_alerts(str(alerts_file))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["src"] == "192.168.1.236"
    assert alert["dst"] == "192.168.1.1"
    assert alert["type"] == "port_scan"
    assert alert["time"] != inc.NO_TIME

NIGHT_SOURCES = ["10.0.0.1", "10.0.0.2", "192.168.1.236", "10.0.0.3", "10.0.0.4", "10.0.0.5"]
NIGHT_DOS_OFFSET = 0
NIGHT_SLOW_SCAN_OFFSET = 7
NIGHT_TYPES_PER_SOURCE = 2

def test_real_decoy_night_is_one_campaign():
    alerts = []
    for source in NIGHT_SOURCES:
        alerts.append(make_alert(source, "dos", NIGHT_DOS_OFFSET, ROUTER))
        alerts.append(make_alert(source, "slow_scan", NIGHT_SLOW_SCAN_OFFSET, ROUTER))
    incident_list = inc.build_incidents(alerts)
    campaign_list = inc.build_campaigns(incident_list)
    assert len(incident_list) == len(NIGHT_SOURCES) * NIGHT_TYPES_PER_SOURCE
    assert len(campaign_list) == 1
    assert len(campaign_list[0]["sources"]) == len(NIGHT_SOURCES)

def make_alert_conf(src, attack_type, seconds_after_base, dst, confidence):
    alert = make_alert(src, attack_type, seconds_after_base, dst)
    alert["confidence"] = confidence
    return alert


def test_incident_averages_confidence():
    alerts = [make_alert_conf(ATTACKER, "port_scan", 0, ROUTER, CONF_A), make_alert_conf(ATTACKER, "port_scan", SHORT_INTERVAL, ROUTER, CONF_B),]
    incident_list = inc.build_incidents(alerts)
    assert len(incident_list) == 1
    assert abs(incident_list[0]["confidence"] - CONF_AVERAGE) < 0.001

def test_missing_confidence_is_none():
    alerts = make_series(ATTACKER, "port_scan", SERIES_LENGTH, SHORT_INTERVAL, 0, ROUTER)
    incident_list = inc.build_incidents(alerts)
    assert incident_list[0]["confidence"] is None

def test_low_confidence_flag():
    assert inc.is_low_confidence(CONF_LOW) is True
    assert inc.is_low_confidence(CONF_HIGH) is False
    assert inc.is_low_confidence(None) is False

from incidents import compute_severity, SEVERITY_MEDIUM, SEVERITY_LOW, SCAN_MEDIUM_MIN_ALERTS
SINGLE_ALERT = 1

def test_single_stealth_scan_is_medium():
    severity = compute_severity("stealth_scan", SINGLE_ALERT)
    assert severity == SEVERITY_MEDIUM

def test_single_fragmented_scan_is_medium():
    severity = compute_severity("fragmented_scan", SINGLE_ALERT)
    assert severity == SEVERITY_MEDIUM

def test_plain_scan_below_threshold_stays_low():
    below_threshold = SCAN_MEDIUM_MIN_ALERTS - 1
    severity = compute_severity("port_scan", below_threshold)
    assert severity == SEVERITY_LOW

def test_floods_and_slowloris_are_high():
    high_impact_types = ["syn_flood", "icmp_flood", "slowloris", "dos"]
    for attack_type in high_impact_types:
        severity = compute_severity(attack_type, SINGLE_ALERT)
        assert severity == SEVERITY_HIGH