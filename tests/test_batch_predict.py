import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from batch_predict import (build_feature_frame, model_feature_names, predict_labels_batch,)
from sklearn.ensemble import IsolationForest
from batch_predict import anomaly_scores_batch, predict_anomalies_batch
FEATURE_NAMES = ["packets", "bytes", "duration"]

def make_model():
    generator = np.random.RandomState(0)
    values = generator.rand(200, 3)
    training_frame = pd.DataFrame(values, columns=FEATURE_NAMES)
    labels = []
    for row_index in range(len(training_frame)):
        if values[row_index][0] > 0.5:
            labels.append("attack")
        else:
            labels.append("normal")
    model = RandomForestClassifier(n_estimators=25, random_state=0)
    model.fit(training_frame, labels)
    return model

def make_feature_dicts(count):
    generator = np.random.RandomState(7)
    feature_dicts = []
    for row_index in range(count):
        values = generator.rand(3)
        features = {}
        features["duration"] = values[2]
        features["packets"] = values[0]
        features["bytes"] = values[1]
        feature_dicts.append(features)
    return feature_dicts

def predict_one_by_one(model, feature_dicts, feature_names):
    results = []
    for features in feature_dicts:
        row = {}
        for name in feature_names:
            row[name] = features[name]
        frame = pd.DataFrame([row], columns=feature_names)
        row_probabilities = model.predict_proba(frame)[0]
        best_index = 0
        best_value = row_probabilities[0]
        for class_index in range(len(row_probabilities)):
            if row_probabilities[class_index] > best_value:
                best_value = row_probabilities[class_index]
                best_index = class_index
        results.append((model.classes_[best_index], float(best_value)))
    return results

def test_batch_matches_one_by_one():
    model = make_model()
    feature_names = model_feature_names(model, FEATURE_NAMES)
    feature_dicts = make_feature_dicts(50)
    expected = predict_one_by_one(model, feature_dicts, feature_names)
    frame = build_feature_frame(feature_dicts, feature_names)
    actual = predict_labels_batch(model, frame)
    assert len(actual) == len(expected)
    for row_index in range(len(expected)):
        expected_label, expected_confidence = expected[row_index]
        actual_label, actual_confidence = actual[row_index]
        assert actual_label == expected_label
        assert actual_confidence == expected_confidence

def test_batch_matches_sklearn_predict():
    model = make_model()
    feature_names = model_feature_names(model, FEATURE_NAMES)
    feature_dicts = make_feature_dicts(30)
    frame = build_feature_frame(feature_dicts, feature_names)
    batch_results = predict_labels_batch(model, frame)
    sklearn_labels = model.predict(frame)
    for row_index in range(len(batch_results)):
        assert batch_results[row_index][0] == sklearn_labels[row_index]

def test_column_order_follows_feature_names_not_dict_order():
    feature_dicts = make_feature_dicts(5)
    frame = build_feature_frame(feature_dicts, FEATURE_NAMES)
    assert list(frame.columns) == FEATURE_NAMES
    for row_index in range(len(feature_dicts)):
        for name in FEATURE_NAMES:
            assert frame[name][row_index] == feature_dicts[row_index][name]

def test_missing_feature_is_an_error_not_a_nan():
    broken = [{"packets": 1.0, "bytes": 2.0}]
    with pytest.raises(KeyError):
        build_feature_frame(broken, FEATURE_NAMES)

def test_empty_window_returns_empty_list():
    model = make_model()
    frame = build_feature_frame([], FEATURE_NAMES)
    assert predict_labels_batch(model, frame) == []

def test_model_feature_names_prefers_the_model():
    model = make_model()
    wrong_fallback = ["duration", "bytes", "packets"]
    assert model_feature_names(model, wrong_fallback) == FEATURE_NAMES

def make_anomaly_model():
    generator = np.random.RandomState(1)
    values = generator.rand(150, 3)
    training_frame = pd.DataFrame(values, columns=FEATURE_NAMES)
    model = IsolationForest(n_estimators=30, contamination=0.05, random_state=0)
    model.fit(training_frame)
    return model

def test_anomaly_batch_matches_one_by_one():
    model = make_anomaly_model()
    feature_dicts = make_feature_dicts(40)
    frame = build_feature_frame(feature_dicts, FEATURE_NAMES)
    expected = []
    for row_index in range(len(feature_dicts)):
        single = build_feature_frame([feature_dicts[row_index]], FEATURE_NAMES)
        expected.append(model.predict(single)[0] == -1)
    actual = predict_anomalies_batch(model, frame)
    assert len(actual) == len(expected)
    for row_index in range(len(expected)):
        assert actual[row_index] == expected[row_index]

def test_anomaly_scores_batch_matches_one_by_one():
    model = make_anomaly_model()
    feature_dicts = make_feature_dicts(20)
    frame = build_feature_frame(feature_dicts, FEATURE_NAMES)
    batch_scores = anomaly_scores_batch(model, frame)
    for row_index in range(len(feature_dicts)):
        single = build_feature_frame([feature_dicts[row_index]], FEATURE_NAMES)
        single_score = float(model.score_samples(single)[0])
        assert batch_scores[row_index] == single_score

def test_anomaly_empty_window():
    model = make_anomaly_model()
    frame = build_feature_frame([], FEATURE_NAMES)
    assert predict_anomalies_batch(model, frame) == []
    assert anomaly_scores_batch(model, frame) == []