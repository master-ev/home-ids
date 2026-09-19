import joblib
from sklearn.ensemble import RandomForestClassifier
from imblearn.over_sampling import SMOTE
from prepare import load_and_prepare

X_train, X_test, y_train, y_test = load_and_prepare()
print("Balacing with SMOTE")
smote = SMOTE(random_state=42, k_neighbors=3)
X_train, y_train = smote.fit_resample(X_train, y_train)
print(f"Training on {len(X_train)} flows")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)
print("Saving model")
joblib.dump({"model": model, "features": list(X_train.columns),}, "ids_model.joblib")
print("Saved ids_model.joblib")
print(f"Model expects {len(X_train.columns)} features")