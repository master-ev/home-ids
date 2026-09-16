import json
import sys
from datetime import datetime

INCIDENT_GAP_SECONDS = 300
BRUTEFORCE_HIGH_MIN_ALERTS = 5
SCAN_MEDIUM_MIN_ALERTS = 3
OTHER_MEDIUM_MIN_ALERTS = 3
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_ORDER = [SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW]
SEVERITY_RANK = {SEVERITY_HIGH: 3, SEVERITY_MEDIUM: 2, SEVERITY_LOW: 1}
UNKNOWN_VALUE = "unknown"
NO_TIME = 0.0
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
DAY_FORMAT = "%Y-%m-%d"
SECONDS_PER_MINUTE = 60
DEFAULT_ALERTS_PATH = "alerts.jsonl"
SOURCE_KEYS = ["src", "src_ip", "source", "source_ip", "attacker", "ip"]
TYPE_KEYS = ["type", "attack_type", "attack", "label", "kind", "prediction"]
TIME_KEYS = ["timestamp", "time", "ts", "window_start", "start"]

def get_field(alert, possible_keys):
    index = 0
    while index < len(possible_keys):
        key = possible_keys[index]
        if key in alert:
            return alert[key]
        index = index + 1
    return None

def parse_time(value):
    if value is None:
        return NO_TIME
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value)
    try:
        return float(text)
    except ValueError:
        pass
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
        return parsed.timestamp()
    except ValueError:
        return NO_TIME

def load_alerts(path):
    alerts = []
    try:
        file = open(path, "r")
    except FileNotFoundError:
        print(f"File not found: {path}")
        return alerts
    lines = file.readlines()
    file.close()
    skipped = 0
    line_number = 0
    while line_number < len(lines):
        line = lines[line_number].strip()
        line_number = line_number + 1
        if line == "":
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            skipped = skipped + 1
            continue
        if not isinstance(raw, dict):
            skipped = skipped + 1
            continue
        source = get_field(raw, SOURCE_KEYS)
        attack_type = get_field(raw, TYPE_KEYS)
        raw_time = get_field(raw, TIME_KEYS)
        timestamp = parse_time(raw_time)
        if source is None:
            source = UNKNOWN_VALUE
        if attack_type is None:
            attack_type = UNKNOWN_VALUE
        alert = {"src": str(source), "type": str(attack_type).lower(), "time": timestamp, "raw": raw,}
        alerts.append(alert)
    if skipped > 0:
        print(f"Skipped {skipped} invalid lines")
    return alerts

def compute_severity(attack_type, alert_count):
    if "dos" in attack_type:
        return SEVERITY_HIGH
    if "brute" in attack_type:
        if alert_count >= BRUTEFORCE_HIGH_MIN_ALERTS:
            return SEVERITY_HIGH
        else:
            return SEVERITY_MEDIUM
    if"scan" in attack_type:
        if alert_count >= SCAN_MEDIUM_MIN_ALERTS:
            return SEVERITY_MEDIUM
        else:
            return SEVERITY_LOW
    if alert_count >= OTHER_MEDIUM_MIN_ALERTS:
        return SEVERITY_MEDIUM
    else:
        return SEVERITY_LOW

def alert_time(alert):
    return alert["time"]

def incident_sort_key(incident):
    rank = SEVERITY_RANK[incident["severity"]]
    return (rank, incident["last_time"])

def make_incident(group_alerts):
    first_alert = group_alerts[0]
    last_index = len(group_alerts) - 1
    last_alert = group_alerts[last_index]
    alert_count = len(group_alerts)
    duration = last_alert["time"] - first_alert["time"]
    severity = compute_severity(first_alert["type"], alert_count)
    incident = {"src": first_alert["src"], "type": first_alert["type"], "severity": severity, "alert_count": alert_count, "first_time": first_alert["time"], "last_time": last_alert["time"], "duration": duration,}
    return incident

def build_incidents(alerts):
    groups = {}
    index = 0
    while index < len(alerts):
        alert = alerts[index]
        group_key = alert["src"] + "|" + alert["type"]
        if group_key not in groups:
            groups[group_key] = []
        groups[group_key].append(alert)
        index = index + 1
    incidents = []
    group_keys = list(groups.keys())
    key_index = 0
    while key_index < len(group_keys):
        group_key = group_keys[key_index]
        ordered = sorted(groups[group_key], key=alert_time)
        current = [ordered[0]]
        position = 1
        while position < len(ordered):
            previous_alert = current[len(current) - 1]
            next_alert = ordered[position]
            gap = next_alert["time"] - previous_alert["time"]
            if gap > INCIDENT_GAP_SECONDS:
                incidents.append(make_incident(current))
                current = [next_alert]
            else:
                current.append(next_alert)
            position = position + 1
        incidents.append(make_incident(current))
        key_index = key_index + 1
    incidents.sort(key=incident_sort_key, reverse=True)
    return incidents

def count_by_severity(incidents):
    counts = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 0, SEVERITY_LOW: 0}
    index = 0
    while index < len(incidents):
        severity = incidents[index]["severity"]
        counts[severity] = counts[severity] + 1
        index = index + 1
    return counts

def count_by_type(incidents):
    counts = {}
    index = 0
    while index < len(incidents):
        attack_type = incidents[index]["type"]
        if attack_type not in counts:
            counts[attack_type] = 0
        counts[attack_type] = counts[attack_type] + 1
        index = index + 1
    return counts

def day_of(timestamp):
    if timestamp == NO_TIME:
        return UNKNOWN_VALUE
    moment = datetime.fromtimestamp(timestamp)
    return moment.strftime(DAY_FORMAT)

def count_per_day(incidents):
    days = {}
    index = 0
    while index < len(incidents):
        incident = incidents[index]
        day = day_of(incident["first_time"])
        if day not in days:
            days[day] = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 0, SEVERITY_LOW: 0}
        severity = incident["severity"]
        days[day][severity] = days[day][severity] + 1
        index = index + 1
    return days

def pair_count(pair):
    return pair[1]

def top_sources(incidents, limit):
    counts = {}
    index = 0
    while index < len(incidents):
        source = incidents[index]["src"]
        if source not in counts:
            counts[source] = 0
        counts[source] = counts[source] + 1
        index = index + 1
    pairs = list(counts.items())
    pairs.sort(key=pair_count, reverse=True)
    result = []
    position = 0
    while position < len(pairs) and position < limit:
        result.append(pairs[position])
        position = position + 1
    return result

def format_time(timestamp):
    if timestamp == NO_TIME:
        return "-"
    moment = datetime.fromtimestamp(timestamp)
    return moment.strftime(TIME_FORMAT)

def format_duration(seconds):
    total_seconds = int(seconds)
    minutes = total_seconds // SECONDS_PER_MINUTE
    rest = total_seconds % SECONDS_PER_MINUTE
    return f"{minutes}m {rest}s"

def main():
    path = DEFAULT_ALERTS_PATH
    if len(sys.argv) > 1:
        path = sys.argv[1]
    alerts = load_alerts(path)
    incidents = build_incidents(alerts)
    severity_counts = count_by_severity(incidents)
    print(f"Loaded {len(alerts)} alerts -> {len(incidents)} incidents")
    print(f"HIGH: {severity_counts[SEVERITY_HIGH]} | "f"MEDIUM: {severity_counts[SEVERITY_MEDIUM]} | "f"LOW: {severity_counts[SEVERITY_LOW]}")
    print()
    index = 0
    while index < len(incidents):
        incident = incidents[index]
        start_text = format_time(incident["first_time"])
        duration_text = format_duration(incident["duration"])
        print(f"[{incident['severity']:<6}] {incident['src']:<16} "f"{incident['type']:<18} alerts={incident['alert_count']:<4} "f"start={start_text} duration={duration_text}")
        index = index + 1

if __name__ == "__main__":
    main()