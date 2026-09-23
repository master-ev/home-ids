import re
import sys
README_PATH = "README.md"
METRICS_PATH = "metrics.md"

CHECKED_LINES = [
    ("Unseen attack captures", "unseen captures"),
    ("Attack alerts", "alert counts"),
    ("Expected label shown to the human", "label shown"),
    ("Attack captures with wrong labels in log", "wrong labels"),
]
NUMBER_PATTERN = re.compile(r"\d+")

def read_file(path):
    with open(path) as f:
        return f.read()

def numbers_in_metrics_line(metrics_text, label):
    for line in metrics_text.splitlines():
        if label in line:
            return NUMBER_PATTERN.findall(line)
    return None

def main():
    readme = read_file(README_PATH)
    metrics = read_file(METRICS_PATH)
    readme_numbers = set(NUMBER_PATTERN.findall(readme))
    problems = 0
    for label, name in CHECKED_LINES:
        values = numbers_in_metrics_line(metrics, label)
        if values is None:
            print(f"[!] metrics.md has no line for '{label}'")
            problems = problems + 1
            continue
        missing = []
        for value in values:
            if value not in readme_numbers:
                missing.append(value)
        if len(missing) > 0:
            print(f"[!] {name}: metrics says {values}, README is missing {missing}")
            problems = problems + 1
        else:
            print(f"    {name}: {values} - present in README")
    if problems > 0:
        print()
        print(f"{problems} mismatch(es): update README.md or regenerate metrics.md")
        sys.exit(1)
    print()
    print("README numbers match metrics.md")

if __name__ == "__main__":
    main()