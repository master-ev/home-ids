# train a Random Forest
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from prepare import load_and_prepare

X_train, X_test, y_train, y_test = load_and_prepare()
print(f"\nTraining on {len(X_train)} flows")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)
print("Predicting on the test set...")
y_pred = model.predict(X_test)
print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
print("Per-class report (precision, recall, f1):")
print(classification_report(y_test, y_pred))

labels = sorted(y_test.unique())
cm = confusion_matrix(y_test, y_pred, labels=labels)
print("\nConfusion matrix (rows = actual, columns = predicted):")
print(f"{'actual/pred':>16}", end="")
for lab in labels:
    print(f"{lab[:8]:>10}", end="")
print()
for i, lab in enumerate(labels):
    print(f"{lab:>16}", end="")
    for j in range(len(labels)):
        print(f"{cm[i][j]:>10}", end="")
    print()

importances = model.feature_importances_
feature_names = X_train.columns
pairs = sorted(zip(feature_names, importances), key=lambda p: p[1], reverse=True)
print("\nTop 15 most important features:")
for name, importance in pairs[:15]:
    print(f"    {name:35} {importance:.4f}")