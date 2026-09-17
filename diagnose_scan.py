from collections import Counter
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import feature_sets as fs

DATASET_PATH = "my_dataset_v2.csv"
LABEL_COLUMN = "label"
CAPTURE_COLUMN = "capture"
TARGET_CAPTURE = "scan.pcap"
TRUE_LABEL = "scan"
DOS_LABEL = "dos"
GOOD_SCANS = ["decoy.pcap", "decoy2_router.pcap", "scan_slow_router.pcap", "scan_syn_lo.pcap"]
TREE_COUNT = 100
RANDOM_SEED = 42
NAME_WIDTH = 24
VALUE_WIDTH = 14
DECIMALS = 2

def train_without_target(dataset, features):
    train_rows = dataset[dataset[CAPTURE_COLUMN] != TARGET_CAPTURE]
    model = RandomForestClassifier(n_estimators=TREE_COUNT, random_state=RANDOM_SEED, class_weight="balanced")
    model.fit(fs.clean_features(train_rows[features]), train_rows[LABEL_COLUMN])
    return model

def percent_scan(model, rows, features):
    predictions = model.predict(fs.clean_features(rows[features]))
    counts = Counter()
    for prediction in predictions:
        counts[str(prediction)] = counts[str(prediction)] + 1
    return counts[TRUE_LABEL] * 100 / len(rows), dict(counts)

def profile_part(dataset, features):
    target_rows = dataset[dataset[CAPTURE_COLUMN] == TARGET_CAPTURE]
    good_rows = dataset[dataset[CAPTURE_COLUMN].isin(GOOD_SCANS)]
    dos_rows = dataset[dataset[LABEL_COLUMN] == DOS_LABEL]
    print("Part 1: means (which side does scan.pcap take?)")
    header = (f"{'feature':<{NAME_WIDTH}}{'scan.pcap':>{VALUE_WIDTH}}" f"{'good_scans':>{VALUE_WIDTH}}{'dos':>{VALUE_WIDTH}}   verdict")
    print(header)
    for feature in features:
        target_mean = target_rows[feature].mean()
        good_mean = good_rows[feature].mean()
        dos_mean = dos_rows[feature].mean()
        distance_good = abs(target_mean - good_mean)
        distance_dos = abs(target_mean - dos_mean)
        if distance_dos < distance_good:
            verdict = "-> DOS side"
        else:
            verdict = "ok (scan side)"
        print(f"{feature:<{NAME_WIDTH}}{target_mean:>{VALUE_WIDTH}.{DECIMALS}f}" f"{good_mean:>{VALUE_WIDTH}.{DECIMALS}f}{dos_mean:>{VALUE_WIDTH}.{DECIMALS}f}" f"   {verdict}")

def ablation_part(dataset, features):
    print()
    print("Part 2: ablation (drop one feature, retrain, test scan.pcap)")
    target_rows = dataset[dataset[CAPTURE_COLUMN] == TARGET_CAPTURE]
    baseline_model = train_without_target(dataset, features)
    baseline_percent, baseline_counts = percent_scan(baseline_model, target_rows, features)
    print(f"baseline (all {len(features)} features): {baseline_percent:.1f}% scan  " f"{baseline_counts}")
    print()
    results = []
    for dropped in features:
        kept = []
        for name in features:
            if name != dropped:
                kept.append(name)
        model = train_without_target(dataset, kept)
        percent, counts = percent_scan(model, target_rows, kept)
        results.append((dropped, percent))
    results.sort(key=lambda pair: pair[1], reverse=True)
    print("Dropping this feature -> % of scan.pcap now classified 'scan':")
    for dropped, percent in results:
        marker = ""
        if percent > baseline_percent + 10:
            marker = "  <== fixes it"
        print(f"  without {dropped:<24} {percent:>6.1f}%{marker}")

def main():
    features = fs.get_feature_set(fs.SET_NO_DIRECTION_CONTEXT)
    dataset = pd.read_csv(DATASET_PATH)
    profile_part(dataset, features)
    ablation_part(dataset, features)

if __name__ == "__main__":
    main()