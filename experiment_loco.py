from collections import Counter
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import feature_sets as fs

DATASET_PATH = "my_dataset_v2.csv"
LABEL_COLUMN = "label"
CAPTURE_COLUMN = "capture"
TREE_COUNT = 100
RANDOM_SEED = 42
ALL_CPU_CORES = -1
PERCENT = 100
WEAK_SCORE_PERCENT = 80
NAME_WIDTH = 24
SCORE_WIDTH = 8
SKIPPED_TEXT = "-"

def make_model():
    model = RandomForestClassifier(n_estimators=TREE_COUNT, random_state=RANDOM_SEED, class_weight="balanced", n_jobs=ALL_CPU_CORES)
    return model

def evaluate_capture(dataset, features, capture):
    is_test = dataset[CAPTURE_COLUMN] == capture
    train_rows = dataset[~is_test]
    test_rows = dataset[is_test]
    true_label = test_rows[LABEL_COLUMN].iloc[0]
    training_labels = set(train_rows[LABEL_COLUMN])
    if true_label not in training_labels:
        return None
    model = make_model()
    model.fit(fs.clean_features(train_rows[features]), train_rows[LABEL_COLUMN])
    predictions = model.predict(fs.clean_features(test_rows[features]))
    counts = Counter()
    for prediction in predictions:
        counts[str(prediction)] = counts[str(prediction)] + 1
    percent_correct = counts[true_label] * PERCENT / len(predictions)
    return percent_correct, counts, true_label

def main():
    dataset = pd.read_csv(DATASET_PATH)
    captures = sorted(dataset[CAPTURE_COLUMN].unique())
    print(f"{len(dataset)} flows from {len(captures)} captures")
    scores = {}
    weak_results = []
    for set_name in fs.ALL_SETS:
        features = fs.get_feature_set(set_name)
        print(f"Evaluating set {set_name} ({fs.SET_DESCRIPTIONS[set_name]}) ...")
        scores[set_name] = {}
        for capture in captures:
            result = evaluate_capture(dataset, features, capture)
            scores[set_name][capture] = result
            if result is not None and result[0] < WEAK_SCORE_PERCENT:
                weak_results.append((set_name, capture, result))
    print()
    print("% correct on the held-out capture")
    header = f"{'capture':<{NAME_WIDTH}}{'label':<12}"
    for set_name in fs.ALL_SETS:
        header = header + f"{set_name:>{SCORE_WIDTH}}"
    print(header)
    for capture in captures:
        label = dataset[dataset[CAPTURE_COLUMN] == capture][LABEL_COLUMN].iloc[0]
        line = f"{capture:<{NAME_WIDTH}}{label:<12}"
        for set_name in fs.ALL_SETS:
            result = scores[set_name][capture]
            if result is None:
                line = line + f"{SKIPPED_TEXT:>{SCORE_WIDTH}}"
            else:
                line = line + f"{result[0]:>{SCORE_WIDTH}.1f}"
        print(line)
    print()
    summary_line = f"{'mean':<{NAME_WIDTH}}{'':<12}"
    worst_line = f"{'worst':<{NAME_WIDTH}}{'':<12}"
    for set_name in fs.ALL_SETS:
        evaluated = []
        for capture in captures:
            result = scores[set_name][capture]
            if result is not None:
                evaluated.append(result[0])
        mean_score = sum(evaluated) / len(evaluated)
        worst_score = min(evaluated)
        summary_line = summary_line + f"{mean_score:>{SCORE_WIDTH}.1f}"
        worst_line = worst_line + f"{worst_score:>{SCORE_WIDTH}.1f}"
    print(summary_line)
    print(worst_line)
    print()
    print(f"Results below {WEAK_SCORE_PERCENT}%: what did the model say?")
    for set_name, capture, result in weak_results:
        percent_correct, counts, true_label = result
        print(f"set {set_name}  {capture:<{NAME_WIDTH}} true={true_label:<11} " f"predicted={dict(counts)}")

if __name__ == "__main__":
    main()