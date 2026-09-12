import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE

FEATURE_MAP = {
    "Destination Port": "destination_port",
    "Total Fwd Packets": "total_fwd_packets",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Fwd Packet Length Max": "fwd_pkt_len_max",
    "Fwd Packet Length Min": "fwd_pkt_len_min",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean",
    "Fwd Packet Length Std": "fwd_pkt_len_std",
    "Bwd Packet Length Max": "bwd_pkt_len_max",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Packet Length Mean": "pkt_len_mean",
    "Packet Length Std": "pkt_len_std",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",
    "Flow Bytes/s": "flow_bytes_per_sec",
    "Flow Packets/s": "flow_packets_per_sec",
}

cicids_cols = list(FEATURE_MAP.keys())
print("Loading dataset")
df = pd.read_csv("data/cicids2017_cleaned.csv")
sample_size = 300000
df = df.groupby("Attack Type", group_keys=False).apply(lambda x: x.sample(min(len(x), int(sample_size * len(x) / len(df))), random_state=42), include_groups=True)
df = df[cicids_cols + ["Attack Type"]]
df = df.replace([np.inf, -np.inf], np.nan).dropna()
df = df.rename(columns=FEATURE_MAP)
our_feature_order = [FEATURE_MAP[c] for c in cicids_cols]
X = df[our_feature_order]
y = df["Attack Type"]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print("Balancing with SMOTE")
smote = SMOTE(random_state=42, k_neighbors=3)
X_train, y_train = smote.fit_resample(X_train, y_train)
print(f"Training on {len(X_train)} flows with {len(our_feature_order)} features")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)
from sklearn.metrics import classification_report, recall_score
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))
print(f"Macro recall: {recall_score(y_test, y_pred, average='macro'):.4f}")
joblib.dump({"model":model, "features":our_feature_order,}, "ids_model_matched.joblib")
print("\nSaved ids_model_matched.joblib")