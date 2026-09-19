import sys
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import feature_sets as fs

DATASET_PATH = "my_dataset_v2.csv"
MODEL_PATH = "my_model_v2.joblib"
LABEL_COLUMN = "label"
TREE_COUNT = 100
RANDOM_SEED = 42
DEFAULT_SET = fs.SET_FORWARD_CONTEXT

def main():
    set_name = DEFAULT_SET
    if len(sys.argv) > 1:
        set_name = sys.argv[1].upper()
    features = fs.get_feature_set(set_name)
    dataset = pd.read_csv(DATASET_PATH)
    x = fs.clean_features(dataset[features])
    y = dataset[LABEL_COLUMN]
    model = RandomForestClassifier(n_estimators=TREE_COUNT, random_state=RANDOM_SEED, class_weight="balanced")
    model.fit(x, y)
    saved = {"model": model, "features": features, "feature_set": set_name}
    joblib.dump(saved, MODEL_PATH)
    print(f"Trained set {set_name} ({fs.SET_DESCRIPTIONS[set_name]}) "f"on {len(dataset)} flows, {len(features)} features")
    print(y.value_counts())
    print(f"Saved to {MODEL_PATH}")

if __name__ == "__main__":
    main()