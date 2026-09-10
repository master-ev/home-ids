import pandas as pd

df = pd.read_csv("data/cicids2017_cleaned.csv")
print("Shape (rows, columns):", df.shape)
print("\nColumns:")
print(df.columns.tolist())
print("\nLast few column names:")
print(df.columns[-3:].tolist())

print("\nAttack Type breakdown:")
print(df["Attack Type"].value_counts())

print("\nAs percentage:")
print((df["Attack Type"].value_counts(normalize=True) * 100).round(2))