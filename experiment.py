from collections import Counter
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
import feature_sets as fs

DATASET_PATH = "my_dataset_v2.csv"
LABEL_COLUMN = "label"
CAPTURE_COLUMN = "capture"
HOLDOUT_CAPTURE = "decoy.pcap"
HOLDOUT_TRUE_LABEL = "scan"
TEST_FRACTION = 0.25
RANDOM_SEED = 42
TREE_COUNT = 100
TOP_FEATURES = 5
PERCENT = 100
DECIMALS = 4

def make_model():
    model = RandomForestClassifier(n_estimators=TREE_COUNT, random_state=RANDOM_SEED, class_weight="balanced")
    return model

def importance_value(pair):
    return pair[1]

def random_split_accuracy(dataset, features):
    x = fs.clean_features(dataset[features])
    y = dataset[LABEL_COLUMN]
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=TEST_FRACTION, random_state=RANDOM_SEED, stratify=y)
    model = make_model()
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    return accuracy_score(y_test, predictions)

def holdout_test(dataset, features):
    is_holdout = dataset[CAPTURE_COLUMN] == HOLDOUT_CAPTURE
    train_rows = dataset[~is_holdout]
    test_rows = dataset[is_holdout]
    model = make_model()
    model.fit(fs.clean_features(train_rows[features]), train_rows[LABEL_COLUMN])
    predictions = model.predict(fs.clean_features(test_rows[features]))
    prediction_texts = []
    for prediction in predictions:
        prediction_texts.append(str(prediction))
    counts = Counter(prediction_texts)
    correct = counts[HOLDOUT_TRUE_LABEL]
    percent_correct = correct * PERCENT / len(prediction_texts)
    pairs = []
    for index in range(len(features)):
        pairs.append((features[index], model.feature_importances_[index]))
    pairs.sort(key=importance_value, reverse=True)
    top_pairs = pairs[:TOP_FEATURES]
    return counts, percent_correct, top_pairs

def main():
    dataset = pd.read_csv(DATASET_PATH)
    captures = list(dataset[CAPTURE_COLUMN].unique())
    if HOLDOUT_CAPTURE not in captures:
        print(f"[!] {HOLDOUT_CAPTURE} is not in {DATASET_PATH}")
        return
    summary = []
    for set_name in fs.ALL_SETS:
        features = fs.get_feature_set(set_name)
        description = fs.SET_DESCRIPTIONS[set_name]
        print()
        print(f"Set {set_name}: {description} ({len(features)} features)")
        accuracy = random_split_accuracy(dataset, features)
        counts, percent_correct, top_pairs = holdout_test(dataset, features)
        print(f"Random split accuracy:        {accuracy:.{DECIMALS}f}")
        print(f"Holdout {HOLDOUT_CAPTURE} predictions: {dict(counts)}")
        print(f"Holdout correct ('{HOLDOUT_TRUE_LABEL}'):     {percent_correct:.1f}%")
        print("Top features (holdout model):")
        for name, value in top_pairs:
            print(f"   {name:<28} {value:.{DECIMALS}f}")
        summary.append((set_name, description, accuracy, percent_correct))
    print()
    print("Summary")
    print(f"{'set':<4} {'description':<38} {'random split':>12} {'decoy holdout':>14}")
    for set_name, description, accuracy, percent_correct in summary:
        print(f"{set_name:<4} {description:<38} {accuracy:>12.{DECIMALS}f} "
              f"{percent_correct:>13.1f}%")

if __name__ == "__main__":
    main()