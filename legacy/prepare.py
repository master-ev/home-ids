import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

def load_and_prepare():
    print("Loading dataset")
    df = pd.read_csv("data/cicids2017_cleaned.csv")
    sample_size = 300000
    if len(df) > sample_size:
        df = df.groupby("Attack Type", group_keys=False).apply(lambda x: x.sample(min(len(x), int(sample_size * len(x) / len(df))), random_state=42), include_groups=True)
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    X = df.drop(columns=["Attack Type"])
    y = df["Attack Type"]
    return train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
