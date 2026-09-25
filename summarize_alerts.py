import json
import sys
from collections import Counter, defaultdict

def load_alerts(path):
    alerts = []
    with open(path) as handle:
        for line in handle:
            stripped = line.strip()
            if len(stripped) == 0:
                continue
            alerts.append(json.loads(stripped))
    return alerts

def summarize(alerts):
    kind_counts = Counter()
    pairs_by_kind = defaultdict(set)
    notified_counts = Counter()
    for alert in alerts:
        kind = alert.get("kind", "unknown")
        kind_counts[kind] = kind_counts[kind] + 1
        src = alert.get("source", "?")
        dst = alert.get("destination", "?")
        pairs_by_kind[kind].add((src, dst))
        if alert.get("notified", False):
            notified_counts[kind] = notified_counts[kind] + 1
    return kind_counts, pairs_by_kind, notified_counts

def print_summary(kind_counts, pairs_by_kind, notified_counts):
    print("")
    print("kind                     logged  notified  pairs")
    for kind in sorted(kind_counts.keys()):
        logged = kind_counts[kind]
        notified = notified_counts[kind]
        pair_count = len(pairs_by_kind[kind])
        print(kind.ljust(24) + str(logged).rjust(7) + str(notified).rjust(10) + str(pair_count).rjust(7))
    total = 0
    for kind in kind_counts:
        total = total + kind_counts[kind]
    print("total".ljust(24) + str(total).rjust(7))

def main():
    if len(sys.argv) < 2:
        print("usage: venv/bin/python summarize_alerts.py alerts.jsonl")
        return
    path = sys.argv[1]
    alerts = load_alerts(path)
    kind_counts, pairs_by_kind, notified_counts = summarize(alerts)
    print_summary(kind_counts, pairs_by_kind, notified_counts)

if __name__ == "__main__":
    main()