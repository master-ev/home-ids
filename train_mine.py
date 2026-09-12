import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from imblearn.over_sampling import SMOTE
import joblib

df = pd.read_csv("my_dataset.csv")
print("Label distribution:")
print(df["label"].value_counts())
X = df.drop(columns=["label"])
y = df["label"]
feature_order = list(X.columns)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print("\nBalancing with SMOTE")
smote = SMOTE(random_state=42, k_neighbors=3)
X_train, y_train = smote.fit_resample(X_train, y_train)
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)
y_pred = model.predict(X_test)
print("\nEvaluation on my own test data:")
print(classification_report(y_test, y_pred))
joblib.dump({"model": model, "features": feature_order}, "my_model.joblib")
print("Saved my_model.joblib")