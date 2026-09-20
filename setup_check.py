import importlib
import os

OK = "[ OK ]"
MISSING = "[MISS]"
WARN = "[WARN]"
REQUIRED_PACKAGES = ["scapy", "pandas", "sklearn", "joblib", "imblearn"]
CODE_FILES = [
    "live_ids.py", "features.py", "context.py", "feature_sets.py",
    "trackers.py", "incidents.py", "correlate.py", "dashboard.py",
    "build_dataset_v2.py", "train_v2.py", "scenarios.py",
]
MODEL_FILE = "my_model_v2.joblib"
DATASET_FILE = "my_dataset_v2.csv"
NORMAL_CAPTURE = "normal.pcap"


def check_packages():
    print("Python packages:")
    all_ok = True
    index = 0
    while index < len(REQUIRED_PACKAGES):
        name = REQUIRED_PACKAGES[index]
        try:
            importlib.import_module(name)
            print(f"  {OK} {name}")
        except ImportError:
            print(f"  {MISSING} {name}  -> run: venv/bin/pip install -r requirements.txt")
            all_ok = False
        index = index + 1
    return all_ok

def check_code_files():
    print("\nCode files (should be in the repo):")
    all_ok = True
    index = 0
    while index < len(CODE_FILES):
        name = CODE_FILES[index]
        if os.path.exists(name):
            print(f"  {OK} {name}")
        else:
            print(f"  {MISSING} {name}  -> the clone is incomplete")
            all_ok = False
        index = index + 1
    return all_ok

def check_generated_files():
    print("\nGenerated files (not in git - you build these locally):")
    model_present = os.path.exists(MODEL_FILE)
    dataset_present = os.path.exists(DATASET_FILE)
    normal_present = os.path.exists(NORMAL_CAPTURE)
    if model_present:
        print(f"  {OK} {MODEL_FILE} (trained model present)")
    else:
        print(f"  {WARN} {MODEL_FILE} missing - the live IDS needs it")
    if dataset_present:
        print(f"  {OK} {DATASET_FILE}")
    else:
        print(f"  {WARN} {DATASET_FILE} missing")
    if normal_present:
        print(f"  {OK} {NORMAL_CAPTURE} (at least one capture present)")
    else:
        print(f"  {WARN} no captures found - you need your own traffic (see below)")
    return model_present, dataset_present, normal_present

def print_next_steps(model_present, dataset_present, normal_present):
    if model_present:
        print("Ready. You can run the live IDS:")
        print("  sudo venv/bin/python live_ids.py")
        return
    print("The trained model is missing. To build it you need captures of")
    print("your OWN traffic (attack captures cannot be shared - they are")
    print("personal network data, and .pcap files are gitignored).")
    print()
    if not normal_present:
        print("1. Capture some normal traffic and attacks against your own target,")
        print("   e.g.:")
        print("     sudo venv/bin/python capture_run.py normal normal.pcap eth0 60")
        print("     (see the README for scan/dos/etc. captures)")
        print("2. List them in scenarios.py")
    if not dataset_present:
        print("3. Build the dataset:   venv/bin/python build_dataset_v2.py")
    print("4. Train the model:     venv/bin/python train_v2.py D")
    print("5. Run the live IDS:    sudo venv/bin/python live_ids.py")

def main():
    print("Home IDS setup check\n")
    packages_ok = check_packages()
    code_ok = check_code_files()
    model_present, dataset_present, normal_present = check_generated_files()
    if not packages_ok or not code_ok:
        print("\n[!] Fix the missing packages/files above first.")
        return
    print_next_steps(model_present, dataset_present, normal_present)

if __name__ == "__main__":
    main()