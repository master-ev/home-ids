import os
import re

SKIP_DIRS = ["venv", "legacy", ".git", "__pycache__", ".pytest_cache"]
ENTRY_POINT_PREFIXES = ["diagnose_", "check_", "experiment", "build_", "train_", "classify_", "capture_", "make_", "soak_", "metrics_", "compare_", "inspect_", "explain_", "window_", "setup_"]
ENTRY_POINT_FILES = ["live_ids.py", "correlate.py", "dashboard.py", "target_server.py", "traffic_gen.py", "synflood.py", "slowloris.py", "audit_usage.py"]
DEFINITION_PATTERN = re.compile(r"^def ([a-z_][a-z0-9_]*)\(", re.MULTILINE)
NAME_WIDTH = 34

def python_files(root):
    paths = []
    for entry in sorted(os.listdir(root)):
        full = os.path.join(root, entry)
        if entry in SKIP_DIRS:
            continue
        if os.path.isdir(full):
            if entry == "tests":
                for test_entry in sorted(os.listdir(full)):
                    if test_entry.endswith(".py"):
                        paths.append(os.path.join(full, test_entry))
            continue
        if entry.endswith(".py"):
            paths.append(full)
    return paths

def read_all(paths):
    contents = {}
    for path in paths:
        with open(path) as f:
            contents[path] = f.read()
    return contents

def is_entry_point(file_name):
    if file_name in ENTRY_POINT_FILES:
        return True
    for prefix in ENTRY_POINT_PREFIXES:
        if file_name.startswith(prefix):
            return True
    return False

def count_references(name, contents, own_path):
    pattern = re.compile(r"\b" + re.escape(name) + r"\b")
    total = 0
    for path in contents:
        if path == own_path:
            continue
        total = total + len(pattern.findall(contents[path]))
    return total

def main():
    paths = python_files(".")
    contents = read_all(paths)
    print("Modules never imported elsewhere")
    for path in paths:
        file_name = os.path.basename(path)
        if path.startswith("./tests"):
            continue
        module_name = file_name[:-3]
        references = count_references(module_name, contents, path)
        if references > 0:
            continue
        if is_entry_point(file_name):
            print(f"  {file_name:<{NAME_WIDTH}} entry point (run by hand)")
        else:
            print(f"  {file_name:<{NAME_WIDTH}} DEAD? no references anywhere")
    print()
    print("Functions in trackers.py / live_ids.py never used elsewhere")
    for path in ["./trackers.py", "./live_ids.py"]:
        if path not in contents:
            continue
        for name in DEFINITION_PATTERN.findall(contents[path]):
            references = count_references(name, contents, path)
            if references == 0:
                print(f"  {os.path.basename(path)}:{name:<{NAME_WIDTH}} no references outside its file")

if __name__ == "__main__":
    main()