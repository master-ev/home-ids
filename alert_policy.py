from collections import Counter, defaultdict
from datetime import datetime

ALERT_COOLDOWN_SECONDS = 60
KIND_FAMILY = {
    "port_scan": "recon",
    "slow_scan": "recon",
    "distributed_scan": "recon",
    "udp_scan": "recon",
    "stealth_scan": "evasion",
    "fragmented_scan": "evasion",
    "ack_scan": "evasion",
    "brute_force": "access",
    "dos": "flood",
    "syn_flood": "flood",
    "icmp_flood": "flood",
    "slowloris": "flood",
    "anomaly": "anomaly",
    "suspicious": "unclassified",
}
FAMILY_COVERS = {"evasion": ["recon"]}
SPECIFICITY_GENERIC = 1
SPECIFICITY_SPECIFIC = 2
GENERIC_KINDS = ["slow_scan", "distributed_scan", "suspicious"]
FRAGMENT_EPISODE_GAP_SECONDS = 60
SLOWLORIS_EPISODE_GAP_SECONDS = 60
last_notified_time = {}
last_notified_specificity = {}
suppressed_kinds = defaultdict(Counter)
unsure_verdicts = {}

def reset_policy_state():
    last_notified_time.clear()
    last_notified_specificity.clear()
    suppressed_kinds.clear()
    unsure_verdicts.clear()

def cooldown_allows(last_time, now, cooldown_seconds):
    if last_time is None:
        return True
    elapsed = now - last_time
    if elapsed >= cooldown_seconds:
        return True
    return False

def family_of(kind):
    family = KIND_FAMILY.get(kind)
    if family is None:
        return kind
    return family

def families_that_block(family):
    blocking = [family]
    for covering_family, covered_list in FAMILY_COVERS.items():
        if family in covered_list:
            blocking.append(covering_family)
    return blocking

def specificity_of(kind):
    if kind in GENERIC_KINDS:
        return SPECIFICITY_GENERIC
    return SPECIFICITY_SPECIFIC

def format_suppressed(kind_counts):
    parts = []
    for kind in sorted(kind_counts):
        count = kind_counts[kind]
        parts.append(kind + " x" + str(count))
    return ", ".join(parts)

def episode_starts(last_seen, now, gap_seconds):
    if last_seen is None:
        return True
    pause = now - last_seen
    if pause > gap_seconds:
        return True
    return False

def unsure_context(src, dst):
    entry = unsure_verdicts.get((src, dst))
    if entry is None:
        return "", None
    verdict, confidence = entry
    text = f" [model unsure: {verdict} {confidence:.2f}]"
    field = {"verdict": verdict, "confidence": confidence}
    return text, field

def emit_alert(alert, console_text, window_time, log_function):
    source = alert["source"]
    destination = alert["destination"]
    kind = alert["kind"]
    family = family_of(kind)
    specificity = specificity_of(kind)
    alert["family"] = family
    blocking_key = None
    is_upgrade = False
    for candidate_family in families_that_block(family):
        candidate_key = (source, destination, candidate_family)
        last_time = last_notified_time.get(candidate_key)
        if cooldown_allows(last_time, window_time, ALERT_COOLDOWN_SECONDS):
            continue
        shown_specificity = last_notified_specificity.get(candidate_key, SPECIFICITY_GENERIC)
        if specificity > shown_specificity:
            is_upgrade = True
            continue
        blocking_key = candidate_key
        break
    if blocking_key is None:
        own_key = (source, destination, family)
        silent_kinds = suppressed_kinds[own_key]
        repeats = 0
        for silent_kind in silent_kinds:
            repeats = repeats + silent_kinds[silent_kind]
        repeat_text = ""
        if repeats > 0:
            repeat_text = f" (+{repeats} similar since last notice: {format_suppressed(silent_kinds)})"
        upgrade_text = ""
        if is_upgrade:
            upgrade_text = " [more specific than the earlier notice]"
        alert["notified"] = True
        alert["upgrade"] = is_upgrade
        alert["suppressed_repeats"] = repeats
        alert["suppressed_kinds"] = dict(silent_kinds)
        suppressed_kinds[own_key] = Counter()
        last_notified_time[own_key] = window_time
        last_notified_specificity[own_key] = specificity
        now_str = datetime.now().strftime("%H:%M:%S")
        print(f"[{now_str}] ALERT: {console_text}{upgrade_text}{repeat_text}")
        notify = True
    else:
        suppressed_kinds[blocking_key][kind] = suppressed_kinds[blocking_key][kind] + 1
        alert["notified"] = False
        notify = False
    log_function(alert)
    return notify

def pending_specificity(item):
    alert = item[0]
    return specificity_of(alert["kind"])

def flush_window_alerts(pending, window_time, log_function):
    ordered = sorted(pending, key=pending_specificity, reverse=True)
    for alert, console_text in ordered:
        if alert["confidence"] is None:
            suffix, field = unsure_context(alert["source"], alert["destination"])
            if field is not None:
                alert["model_unsure"] = field
                console_text = console_text + suffix
        emit_alert(alert, console_text, window_time, log_function)