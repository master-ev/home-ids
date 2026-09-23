from dashboard import (alert_source, incident_source, model_was_unsure, notified_count, SOURCE_TRACKER, SOURCE_MODEL, SOURCE_ANOMALY, SOURCE_MIXED,)
MODEL_CONFIDENCE = 0.88

def tracker_alert():
    return {"kind": "slow_scan", "confidence": None, "model_verdict": "slow_scan", "notified": True}

def model_alert():
    return {"kind": "port_scan", "confidence": MODEL_CONFIDENCE, "model_verdict": "scan", "notified": False}

def anomaly_alert():
    return {"kind": "anomaly", "confidence": None, "model_verdict": "anomaly", "notified": True}

def test_source_of_each_layer():
    assert alert_source(tracker_alert()) == SOURCE_TRACKER
    assert alert_source(model_alert()) == SOURCE_MODEL
    assert alert_source(anomaly_alert()) == SOURCE_ANOMALY

def test_anomaly_is_not_counted_as_tracker():
    assert alert_source(anomaly_alert()) != SOURCE_TRACKER

def test_incident_with_two_layers_is_mixed():
    assert incident_source([tracker_alert(), model_alert()]) == SOURCE_MIXED
    assert incident_source([tracker_alert(), tracker_alert()]) == SOURCE_TRACKER

def test_model_unsure_is_detected():
    unsure = tracker_alert()
    unsure["model_unsure"] = {"verdict": "udp_scan", "confidence": 0.34}
    assert model_was_unsure([tracker_alert()]) is False
    assert model_was_unsure([tracker_alert(), unsure]) is True

def test_notified_count_defaults_to_true_for_old_alerts():
    old_alert = {"kind": "port_scan", "confidence": None, "model_verdict": "slow_scan"}
    assert notified_count([old_alert, model_alert()]) == 1