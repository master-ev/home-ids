# train a Random Forest

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