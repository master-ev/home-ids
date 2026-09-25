from capture_stats import format_drop_report

def test_zero_loss_reads_cleanly():
    line = format_drop_report(1000, 0)
    assert "0.0% loss" in line
    assert "captured 1000" in line

def test_loss_percentage_is_over_the_total_not_the_received():
    line = format_drop_report(100, 40)
    assert "28.57% loss" in line

def test_unavailable_stats_say_so():
    line = format_drop_report(None, None)
    assert "not available" in line

def test_no_traffic_is_not_a_division_by_zero():
    line = format_drop_report(0, 0)
    assert "0.0% loss" in line