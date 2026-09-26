import os
import pytest
import feature_sets

ORIGINAL_MODEL = "my_model.joblib"

pytestmark = pytest.mark.skipif(
    not os.path.exists(ORIGINAL_MODEL),
    reason="my_model.joblib is gitignored; feature sets load base features from it",
)

def test_no_feature_set_has_duplicates():
    for set_name in feature_sets.ALL_SETS:
        features = feature_sets.get_feature_set(set_name)
        distinct = set(features)
        assert len(features) == len(distinct), ("set " + set_name + " has duplicates: " + str(len(features)) + " names, " + str(len(distinct)) + " distinct")

def test_set_d_has_context_and_protocol_features():
    features = feature_sets.get_feature_set(feature_sets.SET_FORWARD_CONTEXT)
    for name in feature_sets.CONTEXT_FEATURES:
        assert name in features
    for name in feature_sets.PROTOCOL_FEATURES:
        assert name in features

def test_set_d_excludes_risky_and_reply_features():
    features = feature_sets.get_feature_set(feature_sets.SET_FORWARD_CONTEXT)
    assert feature_sets.PORT_FEATURE not in features
    for name in feature_sets.REPLY_FLAG_FEATURES:
        assert name not in features