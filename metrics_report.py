import os
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime
import live_ids
from replay import replay_to_log
from scenarios import CAPTURES

REPORT_PATH = "metrics.md"
TEMP_LOG_NAME = "metrics_alerts.jsonl"
NORMAL_LABEL = "normal"
TAIL_LINES = 15
PYTEST_TAIL_LINES = 1

LABEL_TO_KIND = {
    "port_scan": "port_scan",
    "scan": "port_scan",
    "udp_scan": "udp_scan",
    "dos": "dos",
    "brute_force": "brute_force",
    "bruteforce": "brute_force",
    "syn_flood": "syn_flood",
}

EXTRA_CASES = [
    ("stealth_sX.pcap", "stealth_scan"),
    ("stealth_sN.pcap", "stealth_scan"),
    ("stealth_sF.pcap", "stealth_scan"),
    ("frag_scan.pcap", "fragmented_scan"),
    ("frag_normal.pcap", "port_scan"),
    ("slowloris1.pcap", "slowloris"),
    ("slowloris_test.pcap", "slowloris"),
    ("ack_scan.pcap", "ack_scan"),
    ("srcport_scan.pcap", "port_scan"),
    ("padded_100.pcap", "port_scan"),
    ("padded_200.pcap", "port_scan"),
]
EXTRA_NORMAL_CASES = ["dns_normal.pcap"]
GENERIC_RECON_KINDS = ["slow_scan", "distributed_scan"]
SCAN_KINDS = ["port_scan", "udp_scan", "stealth_scan", "ack_scan", "fragmented_scan"]

def acceptable_kinds(expected_kind):
    acceptable = set()
    acceptable.add(expected_kind)
    if expected_kind in SCAN_KINDS:
        for kind in GENERIC_RECON_KINDS:
            acceptable.add(kind)
    return acceptable

def wrong_kinds(kind_counts, expected_kind):
    wrong = Counter()
    if expected_kind is None:
        return wrong
    allowed = acceptable_kinds(expected_kind)
    for kind in kind_counts:
        if kind not in allowed:
            wrong[kind] = kind_counts[kind]
    return wrong

def build_cases():
    attack_cases = []
    normal_cases = []
    scenario_files = set()
    for capture_name, label in CAPTURES:
        scenario_files.add(capture_name)
        if label == NORMAL_LABEL:
            normal_cases.append(capture_name)
            continue
        expected_kind = LABEL_TO_KIND.get(label)
        if expected_kind is None:
            print("[!] No LABEL_TO_KIND mapping for label '" + label + "' (" + capture_name + ")")
        case = {"path": capture_name, "label": label, "expected": expected_kind, "in_training": True}
        attack_cases.append(case)
    added_extra = set()
    for capture_name, expected_kind in EXTRA_CASES:
        if capture_name in scenario_files:
            continue
        if capture_name in added_extra:
            print("[!] Duplicate in EXTRA_CASES, skipped: " + capture_name)
            continue
        added_extra.add(capture_name)
        case = {"path": capture_name, "label": "-", "expected": expected_kind, "in_training": False}
        attack_cases.append(case)
    for capture_name in EXTRA_NORMAL_CASES:
        if capture_name in scenario_files:
            continue
        normal_cases.append(capture_name)
    return attack_cases, normal_cases

def count_kinds(alerts):
    kind_counts = Counter()
    for alert in alerts:
        kind = alert["kind"]
        kind_counts[kind] = kind_counts[kind] + 1
    return kind_counts

def count_notified(alerts):
    notified = 0
    for alert in alerts:
        is_notified = alert.get("notified", True)
        if is_notified:
            notified = notified + 1
    return notified

def count_shown_kinds(alerts):
    shown = Counter()
    for alert in alerts:
        is_notified = alert.get("notified", True)
        if is_notified:
            kind = alert["kind"]
            shown[kind] = shown[kind] + 1
    return shown

def evaluate_attack(case, log_path):
    result = {
        "path": case["path"],
        "label": case["label"],
        "expected": case["expected"],
        "in_training": case["in_training"],
        "status": "ok",
        "detected": False,
        "correct": False,
        "kinds": Counter(),
        "logged": 0,
        "notified": 0,
        "shown_kinds": Counter(),
        "correct_shown": False,
        "wrong_kinds": Counter(),
    }
    if not os.path.exists(case["path"]):
        result["status"] = "missing"
        return result
    alerts = replay_to_log(case["path"], log_path)
    result["kinds"] = count_kinds(alerts)
    result["logged"] = len(alerts)
    result["notified"] = count_notified(alerts)
    total_alerts = len(alerts)
    if total_alerts > 0:
        result["detected"] = True
    if case["expected"] is not None:
        expected_count = result["kinds"][case["expected"]]
        if expected_count > 0:
            result["correct"] = True
    result["shown_kinds"] = count_shown_kinds(alerts)
    if case["expected"] is not None:
        shown_expected = result["shown_kinds"][case["expected"]]
        if shown_expected > 0:
            result["correct_shown"] = True
    result["wrong_kinds"] = wrong_kinds(result["kinds"], case["expected"])
    return result

def evaluate_normal(capture_path, log_path):
    result = {"path": capture_path, "status": "ok", "alerts": 0, "notified": 0, "kinds": Counter()}
    if not os.path.exists(capture_path):
        result["status"] = "missing"
        return result
    alerts = replay_to_log(capture_path, log_path)
    result["alerts"] = len(alerts)
    result["notified"] = count_notified(alerts)
    result["kinds"] = count_kinds(alerts)
    return result

def summarize_attacks(results, in_training):
    summary = {"total": 0, "detected": 0, "checkable": 0, "correct": 0}
    for result in results:
        if result["status"] != "ok":
            continue
        if result["in_training"] != in_training:
            continue
        summary["total"] = summary["total"] + 1
        if result["detected"]:
            summary["detected"] = summary["detected"] + 1
        if result["expected"] is not None:
            summary["checkable"] = summary["checkable"] + 1
            if result["correct"]:
                summary["correct"] = summary["correct"] + 1
    return summary

def summarize_noise(results):
    totals = {"logged": 0, "notified": 0}
    for result in results:
        if result["status"] != "ok":
            continue
        totals["logged"] = totals["logged"] + result["logged"]
        totals["notified"] = totals["notified"] + result["notified"]
    return totals

def summarize_wrong(results):
    summary = {"checkable": 0, "with_wrong": 0}
    for result in results:
        if result["status"] != "ok":
            continue
        if result["expected"] is None:
            continue
        summary["checkable"] = summary["checkable"] + 1
        if len(result["wrong_kinds"]) > 0:
            summary["with_wrong"] = summary["with_wrong"] + 1
    return summary

def summarize_shown(results):
    summary = {"checkable": 0, "shown": 0}
    for result in results:
        if result["status"] != "ok":
            continue
        if result["expected"] is None:
            continue
        summary["checkable"] = summary["checkable"] + 1
        if result["correct_shown"]:
            summary["shown"] = summary["shown"] + 1
    return summary

def run_command_tail(command, line_count):
    completed = subprocess.run(command, capture_output=True, text=True)
    output = completed.stdout + completed.stderr
    lines = []
    for line in output.splitlines():
        stripped = line.rstrip()
        if stripped != "":
            lines.append(stripped)
    start_index = len(lines) - line_count
    if start_index < 0:
        start_index = 0
    return lines[start_index:]

def git_commit_hash():
    lines = run_command_tail(["git", "rev-parse", "--short", "HEAD"], 1)
    if len(lines) == 0:
        return "unknown"
    return lines[0]

def git_has_uncommitted_changes():
    lines = run_command_tail(["git", "status", "--porcelain"], 1)
    return len(lines) > 0

def yes_no(flag):
    if flag:
        return "yes"
    return "no"

def format_kinds(kind_counts):
    if len(kind_counts) == 0:
        return "-"
    parts = []
    for kind in sorted(kind_counts):
        count = kind_counts[kind]
        parts.append(kind + " x" + str(count))
    return ", ".join(parts)

def attack_row(result):
    in_training_text = yes_no(result["in_training"])
    expected_text = result["expected"]
    if expected_text is None:
        expected_text = "?"
    if result["status"] == "missing":
        return ("| " + result["path"] + " | " + expected_text + " | " + in_training_text + " | missing | missing | - | - | - | - | - | - |")
    detected_text = yes_no(result["detected"])
    if result["expected"] is None:
        correct_text = "?"
        shown_text = "?"
    else:
        correct_text = yes_no(result["correct"])
        shown_text = yes_no(result["correct_shown"])
    logged_text = str(result["logged"])
    notified_text = str(result["notified"])
    shown_kinds_text = format_kinds(result["shown_kinds"])
    kinds_text = format_kinds(result["kinds"])
    wrong_text = format_kinds(result["wrong_kinds"])
    return ("| " + result["path"] + " | " + expected_text + " | " + in_training_text + " | " + detected_text + " | " + correct_text + " | " + shown_text + " | " + wrong_text + " | " + logged_text + " | " + notified_text + " | " + shown_kinds_text + " | " + kinds_text + " |")

def normal_row(result):
    if result["status"] == "missing":
        return "| " + result["path"] + " | missing | - | - |"
    alerts_text = str(result["alerts"])
    notified_text = str(result["notified"])
    kinds_text = format_kinds(result["kinds"])
    return "| " + result["path"] + " | " + alerts_text + " | " + notified_text + " | " + kinds_text + " |"

def summary_line(title, summary):
    return ("- **" + title + "**: detected " + str(summary["detected"]) + "/" + str(summary["total"]) + ", correctly labelled " + str(summary["correct"]) + "/" + str(summary["checkable"]))

def build_report(attack_results, normal_results, pytest_lines, loco_lines):
    lines = []
    now_text = datetime.now().strftime("%Y-%m-%d %H:%M")
    commit_text = "`" + git_commit_hash() + "`"
    if git_has_uncommitted_changes():
        commit_text = commit_text + " (+ uncommitted changes)"
    lines.append("# Home IDS - Metrics")
    lines.append("")
    lines.append("Generated " + now_text + " at commit " + commit_text + " by `metrics_report.py`.")
    lines.append("")
    lines.append("> **How to read this.** Each capture is replayed through the live pipeline")
    lines.append("> (`live_ids.analyze_window`: model + 0.70 filter + aggregation + trackers).")
    lines.append("> *Detected* = at least one alert. *Correctly labelled* = an alert of the expected kind.")
    lines.append("> Captures marked *in training* were seen by the model, so for them this measures")
    lines.append("> the pipeline, not generalization. Model generalization = LOCO (below).")
    lines.append("> *Logged* = alerts written to the log (evidence, used by incidents.py).")
    lines.append("> *Notified* = alerts shown to the human (one per source/destination/family per cooldown).")
    lines.append("> *Label shown* = the expected label appears in the console, not only in the log.")
    lines.append("> *Wrong in log* = logged labels that do not describe the capture (end up in incidents).")
    lines.append("")
    unseen = summarize_attacks(attack_results, False)
    seen = summarize_attacks(attack_results, True)
    noise = summarize_noise(attack_results)
    lines.append("## Summary")
    lines.append("")
    lines.append(summary_line("Unseen attack captures", unseen))
    lines.append(summary_line("In-training attack captures", seen))
    lines.append("- **Attack alerts**: " + str(noise["logged"]) + " logged, " + str(noise["notified"]) + " notified (cooldown " + str(live_ids.ALERT_COOLDOWN_SECONDS) + " s per source/destination/family)")
    shown = summarize_shown(attack_results)
    lines.append("- **Expected label shown to the human**: " + str(shown["shown"]) + "/" + str(shown["checkable"]) + " attack captures")
    wrong = summarize_wrong(attack_results)
    lines.append("- **Attack captures with wrong labels in log**: " + str(wrong["with_wrong"]) + "/" + str(wrong["checkable"]))
    normal_total = 0
    normal_with_alerts = 0
    normal_alert_count = 0
    for result in normal_results:
        if result["status"] != "ok":
            continue
        normal_total = normal_total + 1
        normal_alert_count = normal_alert_count + result["alerts"]
        if result["alerts"] > 0:
            normal_with_alerts = normal_with_alerts + 1
    lines.append("- **Normal captures with any alert**: " + str(normal_with_alerts) + "/" + str(normal_total) + " (" + str(normal_alert_count) + " alerts total)")
    lines.append("")
    lines.append("## Attack captures")
    lines.append("")
    lines.append("| Capture | Expected | In training | Detected | Correct label | Label shown | Wrong in log | Logged | Notified | Shown kinds | Alert kinds |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for result in attack_results:
        lines.append(attack_row(result))
    lines.append("")
    lines.append("## Normal captures (false alerts)")
    lines.append("")
    lines.append("Since day 63 the IsolationForest is trained on the scenario normal captures,")
    lines.append("so for them this is in-sample. `dns_normal.pcap` is held out.")
    lines.append("")
    lines.append("| Capture | Alerts | Notified | Alert kinds |")
    lines.append("|---|---|---|---|")
    for result in normal_results:
        lines.append(normal_row(result))
    lines.append("")
    if pytest_lines is not None:
        lines.append("## Tests")
        lines.append("")
        lines.append("```")
        for line in pytest_lines:
            lines.append(line)
        lines.append("```")
        lines.append("")
    if loco_lines is not None:
        lines.append("## LOCO (model generalization, last lines)")
        lines.append("")
        lines.append("```")
        for line in loco_lines:
            lines.append(line)
        lines.append("```")
        lines.append("")
    return "\n".join(lines)

def main():
    run_all = "--all" in sys.argv
    run_tests = run_all or "--tests" in sys.argv
    run_loco = run_all or "--loco" in sys.argv
    print("Loading models...")
    live_ids.load_models()
    temp_dir = tempfile.mkdtemp()
    log_path = os.path.join(temp_dir, TEMP_LOG_NAME)
    attack_cases, normal_cases = build_cases()
    attack_results = []
    for case in attack_cases:
        print("Replaying attack capture " + case["path"] + " ...")
        result = evaluate_attack(case, log_path)
        attack_results.append(result)
    normal_results = []
    for capture_path in normal_cases:
        print("Replaying normal capture " + capture_path + " ...")
        result = evaluate_normal(capture_path, log_path)
        normal_results.append(result)
    pytest_lines = None
    if run_tests:
        print("Running pytest...")
        pytest_command = [sys.executable, "-m", "pytest", "tests/", "-q"]
        pytest_lines = run_command_tail(pytest_command, PYTEST_TAIL_LINES)
    loco_lines = None
    if run_loco:
        print("Running LOCO (slow)...")
        loco_command = [sys.executable, "experiment_loco.py"]
        loco_lines = run_command_tail(loco_command, TAIL_LINES)
    report = build_report(attack_results, normal_results, pytest_lines, loco_lines)
    with open(REPORT_PATH, "w") as f:
        f.write(report + "\n")
    print("Report written to " + REPORT_PATH)

if __name__ == "__main__":
    main()