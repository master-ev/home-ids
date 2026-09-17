import os
import signal
import subprocess
import sys
import time
import urllib.request
from scapy.all import rdpcap
import traffic_gen

WARMUP_SECONDS = 2
COOLDOWN_SECONDS = 1
TARGET_PORT = 8000
PORT_FILTER = f"port {TARGET_PORT}"
NORMAL_FILTER = "tcp or udp"
MODE_NORMAL = "normal"
MODE_DOS = "dos"
MODE_BRUTEFORCE = "bruteforce"
MIN_ARGUMENTS = 5
NORMAL_SITES = [
    "https://example.com",
    "https://www.wikipedia.org",
    "https://www.python.org",
    "https://www.debian.org",
    "https://www.kernel.org",
    "https://www.gnu.org",
]
NORMAL_REQUEST_TIMEOUT = 3

def start_tcpdump(interface, output_path, capture_filter):
    owner = os.environ.get("SUDO_USER")
    command = ["tcpdump", "-i", interface, "-w", output_path, "-U"]
    if owner is not None:
        command = command + ["-Z", owner]
    command = command + [capture_filter]
    print("Running:", " ".join(command))
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return process

def stop_tcpdump(process):
    """Ask tcpdump to flush and exit, like pressing Ctrl-C."""
    process.send_signal(signal.SIGINT)
    process.wait()

def generate_normal(duration_seconds):
    end_time = time.time() + duration_seconds
    site_index = 0
    requests_done = 0
    while time.time() < end_time:
        url = NORMAL_SITES[site_index % len(NORMAL_SITES)]
        try:
            response = urllib.request.urlopen(url, timeout=NORMAL_REQUEST_TIMEOUT)
            response.read()
            response.close()
        except Exception:
            pass
        requests_done = requests_done + 1
        site_index = site_index + 1
    print(f"Normal traffic: {requests_done} requests")

def run_traffic(mode, parameters):
    if mode == MODE_NORMAL:
        duration_seconds = int(parameters[0])
        generate_normal(duration_seconds)
    elif mode == MODE_DOS:
        duration_seconds = int(parameters[0])
        thread_count = int(parameters[1])
        traffic_gen.run_dos(duration_seconds, thread_count)
    elif mode == MODE_BRUTEFORCE:
        duration_seconds = int(parameters[0])
        delay_ms = int(parameters[1])
        traffic_gen.run_bruteforce(duration_seconds, delay_ms)
    else:
        print(f"[!] Unknown mode: {mode}")

def filter_for_mode(mode):
    if mode == MODE_NORMAL:
        return NORMAL_FILTER
    return PORT_FILTER

def main():
    if len(sys.argv) < MIN_ARGUMENTS:
        print(__doc__)
        return
    mode = sys.argv[1]
    output_path = sys.argv[2]
    interface = sys.argv[3]
    parameters = sys.argv[4:]
    capture_filter = filter_for_mode(mode)
    process = start_tcpdump(interface, output_path, capture_filter)
    print(f"Warming up {WARMUP_SECONDS}s, then generating traffic ...")
    time.sleep(WARMUP_SECONDS)
    run_traffic(mode, parameters)
    time.sleep(COOLDOWN_SECONDS)
    stop_tcpdump(process)
    try:
        packets = rdpcap(output_path)
        print(f"Saved {len(packets)} packets to {output_path}")
    except (FileNotFoundError, OSError):
        print(f"[!] Could not read {output_path} (0 packets?)")

if __name__ == "__main__":
    main()