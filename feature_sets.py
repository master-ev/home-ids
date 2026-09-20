import joblib
from context import CONTEXT_FEATURES

ORIGINAL_MODEL_PATH = "my_model.joblib"
PORT_FEATURE = "destination_port"
DIRECTION_PREFIXES = ["bwd_", "total_bwd"]
REPLY_FLAG_FEATURES = ["rst_count", "ack_count"]
MISSING_VALUE = 0
SET_BASE = "A"
SET_BASE_CONTEXT = "B"
SET_NO_DIRECTION_CONTEXT = "C"
SET_FORWARD_CONTEXT = "D"
ALL_SETS = [SET_BASE, SET_BASE_CONTEXT, SET_NO_DIRECTION_CONTEXT, SET_FORWARD_CONTEXT]
SET_DESCRIPTIONS = {SET_BASE: "original per-flow features", SET_BASE_CONTEXT: "original + context", SET_NO_DIRECTION_CONTEXT: "no backward/port features + context", SET_FORWARD_CONTEXT: "no backward/port/reply flags + context",}
PROTOCOL_FEATURES = ["is_tcp"]

def load_base_features():
    saved = joblib.load(ORIGINAL_MODEL_PATH)
    return list(saved["features"])

def is_risky_feature(name):
    if name == PORT_FEATURE:
        return True
    for prefix in DIRECTION_PREFIXES:
        if name.startswith(prefix):
            return True
    return False

def get_feature_set(set_name):
    base = load_base_features()
    if set_name == SET_BASE:
        return base
    if set_name == SET_BASE_CONTEXT:
        return base + CONTEXT_FEATURES
    if set_name == SET_NO_DIRECTION_CONTEXT:
        kept = []
        for name in base:
            if not is_risky_feature(name):
                kept.append(name)
        return kept + CONTEXT_FEATURES
    if set_name == SET_FORWARD_CONTEXT:
        kept = []
        for name in base:
            if not is_risky_feature(name) and name not in REPLY_FLAG_FEATURES:
                kept.append(name)
        if set_name == SET_FORWARD_CONTEXT:
            for name in base:
                if not is_risky_feature(name) and name not in REPLY_FLAG_FEATURES:
                    kept.append(name)
            return kept + CONTEXT_FEATURES + PROTOCOL_FEATURES
    raise ValueError(f"Unknown feature set: {set_name}")

def clean_features(frame):
    cleaned = frame.replace([float("inf"), float("-inf")], MISSING_VALUE)
    cleaned = cleaned.fillna(MISSING_VALUE)
    return cleaned