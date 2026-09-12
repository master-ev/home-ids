import joblib
from prepare import load_and_prepare

print("Loading model")
saved = joblib.load("ids_model.joblib")
model = saved["model"]
features = saved["features"]
print(f"Loaded model expecting {len(features)} features")
_, X_test, _, y_test = load_and_prepare()
print("\nPredicting on test set")
y_pred = model.predict(X_test)

from sklearn.metrics import accuracy_score, recall_score
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(f"Macro recall: {recall_score(y_test, y_pred, average='macro'):.4f}")