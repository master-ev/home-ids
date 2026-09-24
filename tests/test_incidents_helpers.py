import json
import pytest
import incidents as inc

SOME_TIMESTAMP = 1789000000.0
LOW_CONFIDENCE = 0.42
HIGH_CONFIDENCE = 0.91
NINETY_SECONDS = 90.0
TWO_MINUTES = 120
TOP_LIMIT = 2

def test_join_text_joins_any_values():
    assert inc.join_text(["a", "b"]) == "a, b"
    assert inc.join_text([1, 2]) == "1, 2"
    assert inc.join_text([]) == ""

def test_parse_confidence_handles_text_and_garbage():
    assert inc.parse_confidence("0.75") == 0.75
    assert inc.parse_confidence(None) is None
    assert inc.parse_confidence("not a number") is None
    assert inc.parse_confidence([]) is None

def test_format_time_marks_missing_timestamps():
    assert inc.format_time(inc.NO_TIME) == "-"
    assert inc.format_time(SOME_TIMESTAMP) != "-"

def test_format_duration_splits_minutes_and_seconds():
    assert inc.format_duration(NINETY_SECONDS) == "1m 30s"
    assert inc.format_duration(0) == "0m 0s"
    assert inc.format_duration(TWO_MINUTES) == "2m 0s"

def test_format_confidence_marks_low_values():
    assert "LOW" in inc.format_confidence(LOW_CONFIDENCE)
    assert "LOW" not in inc.format_confidence(HIGH_CONFIDENCE)
    assert "-" in inc.format_confidence(None)

def write_lines(path, lines):
    with open(path, "w") as f:
        for line in lines:
            f.write(line + "\n")

def test_missing_file_returns_no_alerts(tmp_path):
    missing = str(tmp_path / "nope.jsonl")
    assert inc.load_alerts(missing) == []

def test_invalid_lines_are_skipped(tmp_path):
    path = str(tmp_path / "alerts.jsonl")
    good = json.dumps({"source": "10.0.0.1", "kind": "port_scan", "timestamp": "2026-09-24T10:00:00"})
    write_lines(path, ["not json at all", "[1, 2, 3]", "", good])
    alerts = inc.load_alerts(path)
    assert len(alerts) == 1
    assert alerts[0]["src"] == "10.0.0.1"

def test_alternative_field_names_are_accepted(tmp_path):
    path = str(tmp_path / "alerts.jsonl")
    other_tool = json.dumps({"src_ip": "10.0.0.2", "dst_ip": "192.168.1.1", "attack": "PORT_SCAN", "ts": SOME_TIMESTAMP})
    write_lines(path, [other_tool])
    alerts = inc.load_alerts(path)
    assert alerts[0]["src"] == "10.0.0.2"
    assert alerts[0]["dst"] == "192.168.1.1"
    assert alerts[0]["type"] == "port_scan"
    assert alerts[0]["time"] == SOME_TIMESTAMP

def test_missing_fields_become_unknown(tmp_path):
    path = str(tmp_path / "alerts.jsonl")
    write_lines(path, [json.dumps({"something": "else"})])
    alerts = inc.load_alerts(path)
    assert alerts[0]["src"] == inc.UNKNOWN_VALUE
    assert alerts[0]["type"] == inc.UNKNOWN_VALUE
    assert alerts[0]["time"] == inc.NO_TIME

def make_incident(source, attack_type, severity, first_time=SOME_TIMESTAMP):
    return {"src": source, "type": attack_type, "severity": severity, "first_time": first_time, "confidence": None}

def test_count_by_severity_counts_all_three():
    items = [make_incident("a", "port_scan", inc.SEVERITY_HIGH), make_incident("b", "dos", inc.SEVERITY_HIGH), make_incident("c", "slow_scan", inc.SEVERITY_LOW)]
    counts = inc.count_by_severity(items)
    assert counts[inc.SEVERITY_HIGH] == 2
    assert counts[inc.SEVERITY_MEDIUM] == 0
    assert counts[inc.SEVERITY_LOW] == 1

def test_count_by_type_groups_kinds():
    items = [make_incident("a", "port_scan", inc.SEVERITY_LOW), make_incident("b", "port_scan", inc.SEVERITY_LOW), make_incident("c", "dos", inc.SEVERITY_HIGH)]
    counts = inc.count_by_type(items)
    assert counts["port_scan"] == 2
    assert counts["dos"] == 1

def test_day_of_marks_missing_timestamps():
    assert inc.day_of(inc.NO_TIME) == inc.UNKNOWN_VALUE
    assert inc.day_of(SOME_TIMESTAMP) != inc.UNKNOWN_VALUE

def test_count_per_day_splits_by_day_and_severity():
    one_day_later = SOME_TIMESTAMP + 86400
    items = [make_incident("a", "port_scan", inc.SEVERITY_HIGH, SOME_TIMESTAMP), make_incident("b", "dos", inc.SEVERITY_LOW, SOME_TIMESTAMP), make_incident("c", "dos", inc.SEVERITY_HIGH, one_day_later)]
    days = inc.count_per_day(items)
    assert len(days) == 2
    first_day = inc.day_of(SOME_TIMESTAMP)
    assert days[first_day][inc.SEVERITY_HIGH] == 1
    assert days[first_day][inc.SEVERITY_LOW] == 1

def test_top_sources_is_sorted_and_limited():
    items = [make_incident("10.0.0.1", "port_scan", inc.SEVERITY_LOW), make_incident("10.0.0.1", "dos", inc.SEVERITY_LOW), make_incident("10.0.0.2", "port_scan", inc.SEVERITY_LOW), make_incident("10.0.0.3", "port_scan", inc.SEVERITY_LOW)]
    top = inc.top_sources(items, TOP_LIMIT)
    assert len(top) == TOP_LIMIT
    assert top[0] == ("10.0.0.1", 2)