import json
import pandas as pd

alerts = []
with open("alerts.jsonl") as f:
    for line in f:
        alerts.append(json.loads(line))
df = pd.DataFrame(alerts)
print(f"Total alerts: {len(df)}\n")
print("Alerts by type:")
print(df["kind"].value_counts())
print("\nAlerts by source:")
print(df["source"].value_counts())
print("\nMost recent alerts:")
print(df[["timestamp", "kind", "source", "destination"]].tail(5).to_string(index=False))