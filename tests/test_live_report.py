from live_report import (build_live_section, format_detection_line, format_drop_line)

def test_zero_loss_reads_cleanly():
    line = format_drop_line("plain flood", {"received": 200237, "dropped": 0})
    assert "0.0% kernel loss" in line
    assert "200237 received" in line

def test_loss_is_over_total_not_received():
    line = format_drop_line("x", {"received": 100, "dropped": 40})
    assert "28.57% kernel loss" in line

def test_detection_shows_the_layer_that_caught_it():
    line = format_detection_line("payload flood", {"detected": True, "by": "tracker only", "half_open": 7411})
    assert "detected" in line
    assert "tracker only" in line
    assert "7411 half-open" in line

def test_a_missed_detection_is_loud():
    line = format_detection_line("something", {"detected": False, "by": "nothing"})
    assert "MISSED" in line

def test_missing_results_file_says_so():
    section = build_live_section(None)
    assert "No live results" in section

def test_section_has_both_subsections_when_present():
    results = {
        "measured_on": "2026-09-25",
        "interface": "eth1",
        "generator": "hping3",
        "note": "point in time",
        "capture_path": {"a": {"received": 100, "dropped": 0}},
        "detections": {"b": {"detected": True, "by": "tracker"}},
    }
    section = build_live_section(results)
    assert "Capture-path loss" in section
    assert "Live detection" in section
    assert "point in time" in section