from summarize_alerts import summarize

def make_alert(kind, src, dst, notified):
    return {"kind": kind, "source": src, "destination": dst, "notified": notified}

def test_counts_alerts_per_kind():
    alerts = [make_alert("syn_flood", "a", "b", True), make_alert("syn_flood", "a", "b", False), make_alert("scan", "a", "c", True)]
    kind_counts, pairs, notified = summarize(alerts)
    assert kind_counts["syn_flood"] == 2
    assert kind_counts["scan"] == 1

def test_distinct_pairs_are_deduplicated():
    alerts = [make_alert("scan", "a", "b", False), make_alert("scan", "a", "b", False), make_alert("scan", "a", "c", False)]
    kind_counts, pairs, notified = summarize(alerts)
    assert len(pairs["scan"]) == 2

def test_notified_is_counted_separately_from_logged():
    alerts = [make_alert("dos", "a", "b", True), make_alert("dos", "a", "b", False), make_alert("dos", "a", "b", False)]
    kind_counts, pairs, notified = summarize(alerts)
    assert kind_counts["dos"] == 3
    assert notified["dos"] == 1

def test_missing_fields_do_not_crash():
    alerts = [{"kind": "scan"}]
    kind_counts, pairs, notified = summarize(alerts)
    assert kind_counts["scan"] == 1
    assert ("?", "?") in pairs["scan"]