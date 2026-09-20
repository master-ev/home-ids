import json
import sys
from datetime import datetime

INCIDENT_GAP_SECONDS = 300
SLOW_SCAN_GAP_SECONDS = 1800
SLOW_TYPE_MARKER = "slow"
CAMPAIGN_GAP_SECONDS = 120
MULTI_SOURCE_MIN_SOURCES = 3
BRUTEFORCE_HIGH_MIN_ALERTS = 5
SCAN_MEDIUM_MIN_ALERTS = 3
OTHER_MEDIUM_MIN_ALERTS = 3
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_ORDER = [SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW]
SEVERITY_RANK = {SEVERITY_HIGH: 3, SEVERITY_MEDIUM: 2, SEVERITY_LOW: 1}
NO_RANK = 0
DOS_MARKER = "dos"
BRUTE_MARKER = "brute"
SCAN_MARKER = "scan"
RECON_MARKERS = [SCAN_MARKER]
ATTACK_MARKERS = [BRUTE_MARKER, DOS_MARKER]
PATTERN_SINGLE = "single"
PATTERN_MULTI_SOURCE = "multi-source"
PATTERN_MULTI_STAGE = "multi-stage"
PATTERN_BOTH = "multi-source + multi-stage"
UNKNOWN_VALUE = "unknown"
MULTIPLE_VALUE = "multiple"
PLACEHOLDER_VALUES = [UNKNOWN_VALUE, MULTIPLE_VALUE]
NO_TIME = 0.0
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
DAY_FORMAT = "%Y-%m-%d"
SECONDS_PER_MINUTE = 60
DEFAULT_ALERTS_PATH = "alerts.jsonl"
SOURCE_KEYS = ["src", "src_ip", "source", "source_ip", "attacker", "ip"]
DEST_KEYS = ["dst", "dst_ip", "destination", "dest", "target"]
TYPE_KEYS = ["type", "attack_type", "attack", "label", "kind", "prediction"]
TIME_KEYS = ["timestamp", "time", "ts", "window_start", "start"]
CONFIDENCE_LOW = 0.60
CONFIDENCE_KEYS = ["confidence", "conf", "probability", "score"]

def get_field(alert, possible_keys):
    index = 0
    while index < len(possible_keys):
        key = possible_keys[index]
        if key in alert:
            return alert[key]
        index = index + 1
    return None

def add_unique(items, value):
    if value not in items:
        items.append(value)

def is_placeholder(value):
    return value in PLACEHOLDER_VALUES

def count_real_values(values):
    total = 0
    index = 0
    while index < len(values):
        if not is_placeholder(values[index]):
            total = total + 1
        index = index + 1
    return total

def types_contain(types, markers):
    type_index = 0
    while type_index < len(types):
        marker_index = 0
        while marker_index < len(markers):
            if markers[marker_index] in types[type_index]:
                return True
            marker_index = marker_index + 1
        type_index = type_index + 1
    return False

def join_text(values):
    parts = []
    index = 0
    while index < len(values):
        parts.append(str(values[index]))
        index = index + 1
    return ", ".join(parts)

def parse_confidence(value):
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None

def average_confidence(values):
    if len(values) == 0:
        return None
    total = 0.0
    index = 0
    while index < len(values):
        total = total + values[index]
        index = index + 1
    return total / len(values)

def is_low_confidence(confidence):
    if confidence is None:
        return False
    return confidence < CONFIDENCE_LOW

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

def format_confidence(value):
    if value is None:
        return "conf=  -   "
    if is_low_confidence(value):
        return f"conf={value:.2f} LOW"
    return f"conf={value:.2f}    "

def load_alerts(path):
    alerts = []
    try:
        file = open(path, "r")
    except FileNotFoundError:
        print(f"[!] File not found: {path}")
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
        destination = get_field(raw, DEST_KEYS)
        attack_type = get_field(raw, TYPE_KEYS)
        timestamp = parse_time(get_field(raw, TIME_KEYS))
        confidence = parse_confidence(get_field(raw, CONFIDENCE_KEYS))
        if source is None:
            source = UNKNOWN_VALUE
        if destination is None:
            destination = UNKNOWN_VALUE
        if attack_type is None:
            attack_type = UNKNOWN_VALUE
        alert = {
            "src": str(source),
            "dst": str(destination),
            "type": str(attack_type).lower(),
            "time": timestamp,
            "confidence": confidence,
            "raw": raw,
        }
        alerts.append(alert)
    if skipped > 0:
        print(f"[!] Skipped {skipped} invalid lines")
    return alerts

def compute_severity(attack_type, alert_count):
    if DOS_MARKER in attack_type:
        return SEVERITY_HIGH
    if "flood" in attack_type or "slowloris" in attack_type or DOS_MARKER in attack_type:
        return SEVERITY_HIGH
    if "fragment" in attack_type:
        return SEVERITY_MEDIUM
    if BRUTE_MARKER in attack_type:
        if alert_count >= BRUTEFORCE_HIGH_MIN_ALERTS:
            return SEVERITY_HIGH
        else:
            return SEVERITY_MEDIUM
    if SCAN_MARKER in attack_type:
        if alert_count >= SCAN_MEDIUM_MIN_ALERTS:
            return SEVERITY_MEDIUM
        else:
            return SEVERITY_LOW
    if alert_count >= OTHER_MEDIUM_MIN_ALERTS:
        return SEVERITY_MEDIUM
    else:
        return SEVERITY_LOW

def gap_for_type(attack_type):
    if SLOW_TYPE_MARKER in attack_type:
        return SLOW_SCAN_GAP_SECONDS
    else:
        return INCIDENT_GAP_SECONDS

def alert_time(alert):
    return alert["time"]

def priority_key(item):
    rank = SEVERITY_RANK[item["severity"]]
    return (rank, item["last_time"])

def make_incident(group_alerts):
    first_alert = group_alerts[0]
    last_index = len(group_alerts) - 1
    last_alert = group_alerts[last_index]
    destinations = []
    index = 0
    while index < len(group_alerts):
        add_unique(destinations, group_alerts[index]["dst"])
        index = index + 1
    alert_count = len(group_alerts)
    duration = last_alert["time"] - first_alert["time"]
    severity = compute_severity(first_alert["type"], alert_count)
    confidences = []
    index = 0
    while index < len(group_alerts):
        value = group_alerts[index].get("confidence")
        if value is not None:
            confidences.append(value)
        index = index + 1
    confidence = average_confidence(confidences)
    incident = {
        "src": first_alert["src"],
        "destinations": destinations,
        "type": first_alert["type"],
        "severity": severity,
        "alert_count": alert_count,
        "confidence": confidence,
        "first_time": first_alert["time"],
        "last_time": last_alert["time"],
        "duration": duration,
    }
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
        allowed_gap = gap_for_type(ordered[0]["type"])
        current = [ordered[0]]
        position = 1
        while position < len(ordered):
            previous_alert = current[len(current) - 1]
            next_alert = ordered[position]
            gap = next_alert["time"] - previous_alert["time"]
            if gap > allowed_gap:
                incidents.append(make_incident(current))
                current = [next_alert]
            else:
                current.append(next_alert)
            position = position + 1
        incidents.append(make_incident(current))
        key_index = key_index + 1
    incidents.sort(key=priority_key, reverse=True)
    return incidents

def incident_first_time(incident):
    return incident["first_time"]

def shares_real_value(values_a, values_b):
    index = 0
    while index < len(values_a):
        value = values_a[index]
        if not is_placeholder(value) and value in values_b:
            return True
        index = index + 1
    return False

def is_close_in_time(incident, campaign):
    earliest_allowed = campaign["first_time"] - CAMPAIGN_GAP_SECONDS
    latest_allowed = campaign["last_time"] + CAMPAIGN_GAP_SECONDS
    starts_early_enough = incident["first_time"] <= latest_allowed
    ends_late_enough = incident["last_time"] >= earliest_allowed
    return starts_early_enough and ends_late_enough

def belongs_to_campaign(incident, campaign):
    if not is_close_in_time(incident, campaign):
        return False

    incident_sources = [incident["src"]]
    if shares_real_value(incident_sources, campaign["sources"]):
        return True

    if shares_real_value(incident["destinations"], campaign["destinations"]):
        return True

    return False

def add_to_campaign(campaign, incident):
    campaign["incidents"].append(incident)
    campaign["alert_count"] = campaign["alert_count"] + incident["alert_count"]
    if incident["first_time"] < campaign["first_time"]:
        campaign["first_time"] = incident["first_time"]
    if incident["last_time"] > campaign["last_time"]:
        campaign["last_time"] = incident["last_time"]
    add_unique(campaign["sources"], incident["src"])
    add_unique(campaign["types"], incident["type"])
    index = 0
    while index < len(incident["destinations"]):
        add_unique(campaign["destinations"], incident["destinations"][index])
        index = index + 1

def new_campaign(incident):
    campaign = {"first_time": incident["first_time"], "last_time": incident["last_time"], "sources": [], "destinations": [], "types": [], "incidents": [], "alert_count": 0, "severity": SEVERITY_LOW, "pattern": PATTERN_SINGLE, "duration": 0.0, "confidence": None,}
    add_to_campaign(campaign, incident)
    return campaign

def finish_campaign(campaign):
    highest_rank = NO_RANK
    highest_severity = SEVERITY_LOW
    index = 0
    while index < len(campaign["incidents"]):
        severity = campaign["incidents"][index]["severity"]
        rank = SEVERITY_RANK[severity]
        if rank > highest_rank:
            highest_rank = rank
            highest_severity = severity
        index = index + 1
    confidences = []
    index = 0
    while index < len(campaign["incidents"]):
        value = campaign["incidents"][index]["confidence"]
        if value is not None:
            confidences.append(value)
        index = index + 1
    campaign["confidence"] = average_confidence(confidences)
    source_count = count_real_values(campaign["sources"])
    is_multi_source = source_count >= MULTI_SOURCE_MIN_SOURCES
    has_recon = types_contain(campaign["types"], RECON_MARKERS)
    has_attack = types_contain(campaign["types"], ATTACK_MARKERS)
    is_multi_stage = has_recon and has_attack
    if is_multi_source and is_multi_stage:
        pattern = PATTERN_BOTH
    elif is_multi_stage:
        pattern = PATTERN_MULTI_STAGE
    elif is_multi_source:
        pattern = PATTERN_MULTI_SOURCE
    else:
        pattern = PATTERN_SINGLE
    severity = highest_severity
    if is_multi_stage:
        severity = SEVERITY_HIGH
    elif is_multi_source and severity == SEVERITY_LOW:
        severity = SEVERITY_MEDIUM
    campaign["pattern"] = pattern
    campaign["severity"] = severity
    campaign["duration"] = campaign["last_time"] - campaign["first_time"]

def build_campaigns(incident_list):
    ordered = sorted(incident_list, key=incident_first_time)
    campaigns = []
    index = 0
    while index < len(ordered):
        incident = ordered[index]
        found = None
        campaign_index = 0
        while campaign_index < len(campaigns) and found is None:
            if belongs_to_campaign(incident, campaigns[campaign_index]):
                found = campaigns[campaign_index]
            campaign_index = campaign_index + 1
        if found is None:
            campaigns.append(new_campaign(incident))
        else:
            add_to_campaign(found, incident)
        index = index + 1
    index = 0
    while index < len(campaigns):
        finish_campaign(campaigns[index])
        index = index + 1
    campaigns.sort(key=priority_key, reverse=True)
    return campaigns

def count_by_severity(items):
    counts = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 0, SEVERITY_LOW: 0}
    index = 0
    while index < len(items):
        severity = items[index]["severity"]
        counts[severity] = counts[severity] + 1
        index = index + 1
    return counts

def count_by_type(incident_list):
    counts = {}
    index = 0
    while index < len(incident_list):
        attack_type = incident_list[index]["type"]
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

def count_per_day(incident_list):
    days = {}
    index = 0
    while index < len(incident_list):
        incident = incident_list[index]
        day = day_of(incident["first_time"])
        if day not in days:
            days[day] = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 0, SEVERITY_LOW: 0}
        severity = incident["severity"]
        days[day][severity] = days[day][severity] + 1
        index = index + 1
    return days

def pair_count(pair):
    return pair[1]

def top_sources(incident_list, limit):
    counts = {}
    index = 0
    while index < len(incident_list):
        source = incident_list[index]["src"]
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

def print_report(path):
    alerts = load_alerts(path)
    incident_list = build_incidents(alerts)
    campaign_list = build_campaigns(incident_list)
    incident_counts = count_by_severity(incident_list)
    campaign_counts = count_by_severity(campaign_list)
    print(f"Loaded {len(alerts)} alerts -> {len(incident_list)} incidents "f"-> {len(campaign_list)} campaigns")
    print(f"Incidents  HIGH: {incident_counts[SEVERITY_HIGH]} | "f"MEDIUM: {incident_counts[SEVERITY_MEDIUM]} | "f"LOW: {incident_counts[SEVERITY_LOW]}")
    print(f"Campaigns  HIGH: {campaign_counts[SEVERITY_HIGH]} | "f"MEDIUM: {campaign_counts[SEVERITY_MEDIUM]} | "f"LOW: {campaign_counts[SEVERITY_LOW]}")
    print()
    low_confidence_incidents = 0
    index = 0
    while index < len(incident_list):
        if is_low_confidence(incident_list[index]["confidence"]):
            low_confidence_incidents = low_confidence_incidents + 1
        index = index + 1
    print(f"Low-confidence incidents (model unsure): {low_confidence_incidents}")
    print(" Campaigns")
    index = 0
    while index < len(campaign_list):
        campaign = campaign_list[index]
        start_text = format_time(campaign["first_time"])
        duration_text = format_duration(campaign["duration"])
        incident_total = len(campaign["incidents"])
        print(f"[{campaign['severity']:<6}] {campaign['pattern']:<27} " f"{format_confidence(campaign['confidence'])} " f"incidents={incident_total:<3} alerts={campaign['alert_count']:<4} " f"start={start_text} duration={duration_text}")
        print(f"sources: {join_text(campaign['sources'])}")
        print(f"types:   {join_text(campaign['types'])}")
        index = index + 1
    print()
    print("Incidents")
    index = 0
    while index < len(incident_list):
        incident = incident_list[index]
        start_text = format_time(incident["first_time"])
        duration_text = format_duration(incident["duration"])
        print(f"[{incident['severity']:<6}] {incident['src']:<16} " f"{incident['type']:<18} {format_confidence(incident['confidence'])} " f"alerts={incident['alert_count']:<4} " f"start={start_text} duration={duration_text}")
        index = index + 1

def main():
    path = DEFAULT_ALERTS_PATH
    if len(sys.argv) > 1:
        path = sys.argv[1]
    print_report(path)

if __name__ == "__main__":
    main()