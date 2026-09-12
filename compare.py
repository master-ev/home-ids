# compare several classifiers

from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, recall_score
from imblearn.over_sampling import SMOTE
from prepare import load_and_prepare

X_train, X_test, y_train, y_test = load_and_prepare()
print("Balancing training data with SMOTE")
smote = SMOTE(random_state=42, k_neighbors=3)
X_train, y_train = smote.fit_resample(X_train, y_train)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

def evaluate(name, model, X_tr, X_te):
    print(f"Model: {name}")
    model.fit(X_tr, y_train)
    y_pred = model.predict(X_te)
    print(classification_report(y_test, y_pred))
    macro_recall = recall_score(y_test, y_pred, average="macro")
    print(f"Macro recall: {macro_recall:.4f}\n")
    return macro_recall

results = {}
results["Random Forest"] = evaluate("RANDOM FOREST", RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1), X_train, X_test)
results["Gradient Boosting"] = evaluate("GRADIENT BOOSTING", HistGradientBoostingClassifier(random_state=42), X_train, X_test)
results["Logistic Regression"] = evaluate("LOGISTIC REGRESSION", LogisticRegression(max_iter=1000, n_jobs=-1), X_train_scaled, X_test_scaled)
print("SUMMARY:")
for name, score in sorted(results.items(), key=lambda p: p[1], reverse=True):
    print(f"    {name:22} {score:.4f}")