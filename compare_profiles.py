import sys
from collections import Counter
import pandas as pd
import feature_sets as fs

DATASET_PATH = "my_dataset_v2.csv"
CAPTURE_COLUMN = "capture"
LABEL_COLUMN = "label"
DEFAULT_TARGET = "decoy.pcap"
DEFAULT_SET = fs.SET_NO_DIRECTION_CONTEXT
PCAP_SUFFIX = ".pcap"
NAME_WIDTH = 24
VALUE_WIDTH = 12
DECIMALS = 2

def short_name(capture):
    return capture.replace(PCAP_SUFFIX, "")

def main():
    set_name = DEFAULT_SET
    target = DEFAULT_TARGET
    if len(sys.argv) > 1:
        set_name = sys.argv[1].upper()
    if len(sys.argv) > 2:
        target = sys.argv[2]
    features = fs.get_feature_set(set_name)
    dataset = pd.read_csv(DATASET_PATH)
    cleaned = fs.clean_features(dataset[features])
    cleaned[CAPTURE_COLUMN] = dataset[CAPTURE_COLUMN]
    medians = cleaned.groupby(CAPTURE_COLUMN)[features].median()
    label_of = dataset.groupby(CAPTURE_COLUMN)[LABEL_COLUMN].first()
    if target not in medians.index:
        print(f"[!] {target} is not in {DATASET_PATH}")
        return
    others = []
    for capture in medians.index:
        if capture != target:
            others.append(capture)
    header = f"{'feature':<{NAME_WIDTH}}"
    for capture in others:
        header = header + f"{short_name(capture):>{VALUE_WIDTH}}"
    header = header + f"{short_name(target):>{VALUE_WIDTH}}   closest to"
    print(f"Set {set_name}, medians per capture")
    print(header)
    votes = Counter()
    outside_count = 0
    for feature in features:
        target_value = medians.loc[target, feature]
        line = f"{feature:<{NAME_WIDTH}}"
        closest_capture = None
        closest_distance = None
        lowest = None
        highest = None
        for capture in others:
            value = medians.loc[capture, feature]
            line = line + f"{value:>{VALUE_WIDTH}.{DECIMALS}f}"
            distance = abs(value - target_value)
            if closest_distance is None or distance < closest_distance:
                closest_distance = distance
                closest_capture = capture
            if lowest is None or value < lowest:
                lowest = value
            if highest is None or value > highest:
                highest = value
        closest_label = label_of[closest_capture]
        votes[closest_label] = votes[closest_label] + 1
        note = ""
        if target_value < lowest or target_value > highest:
            note = "  OUTSIDE"
            outside_count = outside_count + 1
        line = line + f"{target_value:>{VALUE_WIDTH}.{DECIMALS}f}   "
        line = line + f"{closest_label} ({short_name(closest_capture)}){note}"
        print(line)
    print()
    print(f"{target} ({label_of[target]}) is closest to: {dict(votes)}")
    print(f"Features where {target} is outside every other capture: "f"{outside_count} of {len(features)}")

if __name__ == "__main__":
    main()