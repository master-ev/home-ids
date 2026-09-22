import os
import tempfile
from collections import Counter
import live_ids
from replay import replay_to_log
from metrics_report import build_cases

NAME_WIDTH = 26
COLUMN_WIDTH = 14

def kinds_of(alerts):
    counts = Counter()
    for alert in alerts:
        counts[alert["kind"]] = counts[alert["kind"]] + 1
    return counts

def format_kinds(counts):
    if len(counts) == 0:
        return "(none)"
    parts = []
    for kind in sorted(counts):
        parts.append(kind + " x" + str(counts[kind]))
    return ", ".join(parts)

def always_normal(row):
    return [1]

def main():
    live_ids.load_models()
    temp_dir = tempfile.mkdtemp()
    log_path = os.path.join(temp_dir, "value_alerts.jsonl")
    attack_cases, normal_cases = build_cases()
    real_model = live_ids.anomaly_model
    class NeverAnomalous:
        def predict(self, row):
            return always_normal(row)
    print("capture".ljust(NAME_WIDTH) + "with anomaly".rjust(COLUMN_WIDTH) + "without".rjust(COLUMN_WIDTH) + "   difference")
    changed = 0
    for case in attack_cases:
        path = case["path"]
        if not os.path.exists(path):
            continue
        live_ids.anomaly_model = real_model
        with_alerts = kinds_of(replay_to_log(path, log_path))
        live_ids.anomaly_model = NeverAnomalous()
        without_alerts = kinds_of(replay_to_log(path, log_path))
        difference = Counter(with_alerts)
        difference.subtract(without_alerts)
        only_with = Counter()
        for kind in difference:
            if difference[kind] > 0:
                only_with[kind] = difference[kind]
        total_with = sum(with_alerts.values())
        total_without = sum(without_alerts.values())
        if total_with != total_without:
            changed = changed + 1
        line = path.ljust(NAME_WIDTH) + str(total_with).rjust(COLUMN_WIDTH) + str(total_without).rjust(COLUMN_WIDTH)
        line = line + "   " + format_kinds(only_with)
        print(line)
    live_ids.anomaly_model = real_model
    print()
    print(f"Attack captures where the anomaly layer changed the log: {changed}")

if __name__ == "__main__":
    main()