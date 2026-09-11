import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

print("Loading dataset")
df = pd.read_csv("data/cicids2017_cleaned.csv")
print(f"Loaded {len(df)} flows")
sample_size = 300000
if len(df) > sample_size:
    df = df.groupby("Attack Type", group_keys=False).apply(lambda x: x.sample(min(len(x), int(sample_size * len(x) / len(df))), random_state=42))
print(f"Sampled down to {len(df)} flows")
df = df.replace([np.inf, -np.inf], np.nan)
before = len(df)
df = df.dropna()
print(f"Dropped {before - len(df)} rows with missing/infinite values")
X = df.drop(columns=["Attack Type"])
y = df["Attack Type"]
print(f"\nX shape (features): {X.shape}")
print(f"y shape (labels): {y.shape}")

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f"\nTrain: {len(X_train)} flows")
print(f"Test: {len(X_test)} flows")
print("\nTrain label distribution:")
print(y_train.value_counts())