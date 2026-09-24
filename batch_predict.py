import pandas as pd

def model_feature_names(model, fallback_names):
    if hasattr(model, "feature_names_in_"):
        return list(model.feature_names_in_)
    return list(fallback_names)

def build_feature_frame(feature_dicts, feature_names):
    rows = []
    for features in feature_dicts:
        row = {}
        for name in feature_names:
            if name not in features:
                raise KeyError("missing feature: " + name)
            row[name] = features[name]
        rows.append(row)
    frame = pd.DataFrame(rows, columns=feature_names)
    return frame

def predict_labels_batch(model, frame):
    results = []
    if len(frame) == 0:
        return results
    probabilities = model.predict_proba(frame)
    classes = model.classes_
    for row_index in range(len(probabilities)):
        row_probabilities = probabilities[row_index]
        best_index = 0
        best_value = row_probabilities[0]
        for class_index in range(len(row_probabilities)):
            if row_probabilities[class_index] > best_value:
                best_value = row_probabilities[class_index]
                best_index = class_index
        label = classes[best_index]
        confidence = float(best_value)
        results.append((label, confidence))
    return results

def predict_anomalies_batch(anomaly_model, frame):
    flags = []
    if len(frame) == 0:
        return flags
    raw_predictions = anomaly_model.predict(frame)
    for row_index in range(len(raw_predictions)):
        if raw_predictions[row_index] == -1:
            flags.append(True)
        else:
            flags.append(False)
    return flags

def anomaly_scores_batch(anomaly_model, frame):
    scores = []
    if len(frame) == 0:
        return scores
    raw_scores = anomaly_model.score_samples(frame)
    for row_index in range(len(raw_scores)):
        scores.append(float(raw_scores[row_index]))
    return scores