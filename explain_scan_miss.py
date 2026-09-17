from collections import Counter
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import feature_sets as fs

DATASET_PATH = "my_dataset_v2.csv"
LABEL_COLUMN = "label"
CAPTURE_COLUMN = "capture"
TARGET_CAPTURE = "scan.pcap"
TRUE_LABEL = "scan"
CONTEXT_FLOWS_FEATURE = "ctx_src_flows"
CONTEXT_PORTS_FEATURE = "ctx_src_ports"
CONTEXT_RATIO_FEATURE = "ctx_flows_per_port"
TREE_COUNT = 100
RANDOM_SEED = 42
THIN_TARGETS = [5, 10, 20, 50, 100]

def train_without_target(dataset, features):
    is_target = dataset[CAPTURE_COLUMN] == TARGET_CAPTURE
    train_rows = dataset[~is_target]
    model = RandomForestClassifier(n_estimators=TREE_COUNT, random_state=RANDOM_SEED, class_weight="balanced")
    model.fit(fs.clean_features(train_rows[features]), train_rows[LABEL_COLUMN])
    return model

def classify_rows(model, rows, features):
    predictions = model.predict(fs.clean_features(rows[features]))
    counts = Counter()
    for prediction in predictions:
        counts[str(prediction)] = counts[str(prediction)] + 1
    return counts

def overwrite_context(rows, flows_value):
    changed = rows.copy()
    changed[CONTEXT_FLOWS_FEATURE] = flows_value
    changed[CONTEXT_PORTS_FEATURE] = flows_value
    changed[CONTEXT_RATIO_FEATURE] = 1.0
    return changed

def main():
    features = fs.get_feature_set(fs.SET_NO_DIRECTION_CONTEXT)
    dataset = pd.read_csv(DATASET_PATH)
    model = train_without_target(dataset, features)
    target_rows = dataset[dataset[CAPTURE_COLUMN] == TARGET_CAPTURE]
    print(f"{TARGET_CAPTURE}: {len(target_rows)} flows")
    as_is = classify_rows(model, target_rows, features)
    print(f"As-is (context untouched): {dict(as_is)}")
    print()
    print("Pretending the scan ran at a normal rate (flows/window):")
    for flows_value in THIN_TARGETS:
        changed = overwrite_context(target_rows, flows_value)
        counts = classify_rows(model, changed, features)
        correct = counts[TRUE_LABEL]
        percent = correct * 100 / len(target_rows)
        print(f"  {flows_value:>4} flows/window -> {dict(counts)}  ({percent:.1f}% scan)")

if __name__ == "__main__":
    main()