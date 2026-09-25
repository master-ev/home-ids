import json
import os

LIVE_RESULTS_PATH = "live_results.json"

def load_live_results(path):
    if not os.path.exists(path):
        return None
    with open(path) as handle:
        return json.load(handle)

def format_drop_line(name, stats):
    received = stats["received"]
    dropped = stats["dropped"]
    total = received + dropped
    if total == 0:
        loss = 0.0
    else:
        loss = 100.0 * dropped / total
    return ("- **" + name + "**: " + str(received) + " received, " + str(dropped) + " dropped (" + str(round(loss, 2)) + "% kernel loss)")

def format_detection_line(name, info):
    if info["detected"]:
        status = "detected"
    else:
        status = "MISSED"
    line = "- **" + name + "**: " + status + " (" + info["by"] + ")"
    if "half_open" in info:
        line = line + ", " + str(info["half_open"]) + " half-open"
    if "ports" in info:
        line = line + ", " + str(info["ports"]) + " ports"
    return line

def build_live_section(results):
    lines = []
    lines.append("## Live validation")
    lines.append("")
    if results is None:
        lines.append("_No live results recorded (live_results.json missing)._")
        return "\n".join(lines)
    lines.append("Point-in-time measurements on a real interface, " + "**not regenerated** by this report.")
    lines.append("")
    lines.append("- Measured: " + results["measured_on"] + " on " + results["interface"])
    lines.append("- Generator: " + results["generator"])
    lines.append("")
    lines.append("### Capture-path loss (tcpdump, kernel counters)")
    lines.append("")
    for name in sorted(results["capture_path"].keys()):
        lines.append(format_drop_line(name, results["capture_path"][name]))
    lines.append("")
    lines.append("### Live detection")
    lines.append("")
    for name in sorted(results["detections"].keys()):
        lines.append(format_detection_line(name, results["detections"][name]))
    lines.append("")
    lines.append("_" + results["note"] + "_")
    return "\n".join(lines)

def write_live_section(results_path, output_path):
    results = load_live_results(results_path)
    section = build_live_section(results)
    with open(output_path, "w") as handle:
        handle.write(section + "\n")
    return section

if __name__ == "__main__":
    section = write_live_section(LIVE_RESULTS_PATH, "live_section.md")
    print(section)