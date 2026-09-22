import json
import os
import sys
from collections import Counter
from datetime import datetime
from live_ids import family_of, SESSION_SUFFIX

SECONDS_PER_HOUR = 3600
TOP_PAIRS_SHOWN = 10

def read_jsonl(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path) as f:
        for line in f:
            stripped = line.strip()
            if stripped == "":
                continue
            rows.append(json.loads(stripped))
    return rows

def read_session(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)

def session_hours(session):
    if session is None:
        return None
    end_text = session.get("end")
    if end_text is None:
        end_text = session.get("last_update")
    if end_text is None:
        return None
    start = datetime.fromisoformat(session["start"])
    end = datetime.fromisoformat(end_text)
    seconds = (end - start).total_seconds()
    return seconds / SECONDS_PER_HOUR

def rate_per_hour(count, hours):
    if hours is None or hours <= 0:
        return None
    return count / hours

def rate_text(count, hours):
    rate = rate_per_hour(count, hours)
    if rate is None:
        return "?/h"
    return f"{rate:.2f}/h"

def count_field(alerts, field):
    counts = Counter()
    for alert in alerts:
        value = alert.get(field, "?")
        counts[value] = counts[value] + 1
    return counts

def count_families(alerts):
    counts = Counter()
    for alert in alerts:
        family = family_of(alert["kind"])
        counts[family] = counts[family] + 1
    return counts

def count_pairs(alerts):
    counts = Counter()
    for alert in alerts:
        pair = alert["source"] + " -> " + alert["destination"]
        counts[pair] = counts[pair] + 1
    return counts

def only_notified(alerts):
    notified = []
    for alert in alerts:
        if alert.get("notified", True):
            notified.append(alert)
    return notified

def print_counts(title, counts, hours):
    print(title)
    if len(counts) == 0:
        print("  (none)")
        return
    for key, count in counts.most_common():
        print(f"  {key:<30} {count:>5}   {rate_text(count, hours)}")

def main():
    if len(sys.argv) < 2:
        print("Usage: venv/bin/python soak_report.py soak_day71.jsonl")
        return
    log_path = sys.argv[1]
    session = read_session(log_path + SESSION_SUFFIX)
    alerts = read_jsonl(log_path)
    notified = only_notified(alerts)
    hours = session_hours(session)
    print("Soak test report")
    if session is None:
        print("[!] No session file: duration unknown")
    else:
        stopped_cleanly = session.get("end") is not None
        print(f"Start: {session['start']}")
        print(f"Duration: {hours:.2f} h  (stopped cleanly: {stopped_cleanly})")
        print(f"Windows: {session['windows']}   Packets: {session['packets']}")
    print()
    print(f"Alerts logged:   {len(alerts):>5}   {rate_text(len(alerts), hours)}")
    print(f"Alerts notified: {len(notified):>5}   {rate_text(len(notified), hours)}")
    print()
    print_counts("Logged by kind:", count_field(alerts, "kind"), hours)
    print_counts("Notified by family:", count_families(notified), hours)
    print()
    print(f"Top {TOP_PAIRS_SHOWN} pairs (logged):")
    top_pairs = count_pairs(alerts).most_common(TOP_PAIRS_SHOWN)
    if len(top_pairs) == 0:
        print("  (none)")
    for pair, count in top_pairs:
        print(f"  {pair:<45} {count:>5}")
    print()
    print("Notified alerts (what the human saw):")
    if len(notified) == 0:
        print("  (none)")
    for alert in notified:
        print(f"  {alert['timestamp'][:19]}  {alert['kind']:<16} {alert['source']} -> {alert['destination']}  {alert['description']}")

if __name__ == "__main__":
    main()