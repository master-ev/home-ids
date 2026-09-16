import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

MODEL_PATH = "my_model.joblib"
DATASET_PATH = "my_dataset.csv"
LABEL_CANDIDATES = ["label", "Label", "class", "target", "attack", "type"]
MODEL_KEYS = ["model", "clf", "classifier", "rf"]
FEATURE_KEYS = ["features", "feature_names", "columns"]
TOP_FEATURES = 10
TEST_FRACTION = 0.25
RANDOM_SEED = 42
TREE_COUNT = 100
PERMUTATION_REPEATS = 5
DECIMALS = 4
TABLE_WIDTH = 200

def unwrap_model(loaded):
    model = loaded
    if isinstance(loaded, dict):
        for key in MODEL_KEYS:
            if key in loaded:
                model = loaded[key]
                break
    if hasattr(model, "steps"):
        last_step = model.steps[-1]
        model = last_step[1]
    return model

def find_label_column(df):
    for name in LABEL_CANDIDATES:
        if name in df.columns:
            return name
    text_columns = list(df.select_dtypes(exclude="number").columns)
    if len(text_columns) > 0:
        return text_columns[-1]
    return None

def find_feature_columns(df, label_column, loaded, model):
    if hasattr(model, "feature_names_in_"):
        return list(model.feature_names_in_)
    if isinstance(loaded, dict):
        for key in FEATURE_KEYS:
            if key in loaded:
                return list(loaded[key])
    result = []
    for name in df.select_dtypes(include="number").columns:
        if name != label_column:
            result.append(name)
    return result

def print_ranking(title, names, scores):
    pairs = []
    for index in range(len(names)):
        pairs.append((names[index], scores[index]))
    pairs.sort(key=lambda pair: pair[1], reverse=True)
    print()
    print(f"{title}")
    top_names = []
    for position in range(min(TOP_FEATURES, len(pairs))):
        name = pairs[position][0]
        score = pairs[position][1]
        print(f"{position + 1:>2}. {name:<35} {score:.{DECIMALS}f}")
        top_names.append(name)
    return top_names

def main():
    pd.set_option("display.width", TABLE_WIDTH)
    pd.set_option("display.max_columns", None)
    loaded = joblib.load(MODEL_PATH)
    model = unwrap_model(loaded)
    print(f"Model type: {type(model).__name__}")
    df = pd.read_csv(DATASET_PATH)
    label_column = find_label_column(df)
    if label_column is None:
        print("[!] Could not find the label column. Columns are:")
        print(list(df.columns))
        return
    feature_columns = find_feature_columns(df, label_column, loaded, model)
    missing = []
    for name in feature_columns:
        if name not in df.columns:
            missing.append(name)
    if len(missing) > 0:
        print(f"[!] Features missing from the CSV: {missing}")
        return
    if hasattr(model, "n_features_in_"):
        expected = model.n_features_in_
        if expected != len(feature_columns):
            print(f"[!] Model expects {expected} features, found {len(feature_columns)}")
    print(f"Label column: {label_column}")
    print(f"Features ({len(feature_columns)}): {feature_columns}")
    print()
    print("Class counts")
    print(df[label_column].value_counts())
    features = df[feature_columns]
    features = features.replace([float("inf"), float("-inf")], 0)
    features = features.fillna(0)
    labels = df[label_column]
    top_names = []
    if hasattr(model, "feature_importances_"):
        importances = list(model.feature_importances_)
        if len(importances) == len(feature_columns):
            top_names = print_ranking("Saved model: MDI (Gini) importance", feature_columns, importances)
    x_train, x_test, y_train, y_test = train_test_split(features, labels, test_size=TEST_FRACTION, random_state=RANDOM_SEED, stratify=labels)
    diagnostic = RandomForestClassifier(n_estimators=TREE_COUNT, random_state=RANDOM_SEED, class_weight="balanced")
    diagnostic.fit(x_train, y_train)
    predictions = diagnostic.predict(x_test)
    class_names = sorted(labels.unique())
    matrix = confusion_matrix(y_test, predictions, labels=class_names)
    matrix_table = pd.DataFrame(matrix, index=["real_" + str(c) for c in class_names], columns=["pred_" + str(c) for c in class_names])
    print()
    print("Diagnostic copy: confusion matrix (test split)")
    print(matrix_table)
    print()
    print(classification_report(y_test, predictions, digits=DECIMALS))
    result = permutation_importance(diagnostic, x_test, y_test, n_repeats=PERMUTATION_REPEATS, random_state=RANDOM_SEED)
    permutation_top = print_ranking("Diagnostic copy: permutation importance", feature_columns, list(result.importances_mean))
    if len(top_names) == 0:
        top_names = permutation_top
    profile = df.groupby(label_column)[top_names].mean()
    print()
    print("Mean of top features per class (rows = features)")
    print(profile.T.round(DECIMALS))

if __name__ == "__main__":
    main()