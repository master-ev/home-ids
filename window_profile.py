import sys
from scapy.all import IP, TCP
from scapy.utils import PcapReader

WINDOW_SECONDS = 5
MIN_ATTEMPTS_TO_SHOW = 5
MAX_ROWS_PER_FILE = 15
MULTI_SOURCE_MIN_SOURCES = 3
SCAN_MAX_ATTEMPTS_PER_PORT = 3
SINGLE_PORT = 1
SYN_FLAG = 0x02
ACK_FLAG = 0x10

def read_attempts(path):
    per_source = {}
    per_destination = {}
    first_time = None
    reader = PcapReader(path)
    for packet in reader:
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            continue
        flags = int(packet[TCP].flags)
        is_syn = (flags & SYN_FLAG) != 0
        is_ack = (flags & ACK_FLAG) != 0
        if not is_syn or is_ack:
            continue
        timestamp = float(packet.time)
        if first_time is None:
            first_time = timestamp
        elapsed = timestamp - first_time
        window_index = int(elapsed // WINDOW_SECONDS)
        source = packet[IP].src
        destination = packet[IP].dst
        port = packet[TCP].dport
        source_key = (source, window_index)
        if source_key not in per_source:
            per_source[source_key] = {"attempts": 0, "ports": set(), "destinations": set()}
        stats = per_source[source_key]
        stats["attempts"] = stats["attempts"] + 1
        stats["ports"].add(port)
        stats["destinations"].add(destination)
        destination_key = (destination, window_index)
        if destination_key not in per_destination:
            per_destination[destination_key] = set()
        per_destination[destination_key].add(source)
    reader.close()
    return per_source, per_destination

def behavior_hint(attempts, port_count):
    if port_count == SINGLE_PORT:
        return "one port hammered (flood / brute-force)"
    attempts_per_port = attempts / port_count
    if attempts_per_port <= SCAN_MAX_ATTEMPTS_PER_PORT:
        return "many different ports (scan)"
    return "mixed"

def print_source_table(per_source):
    rows = []
    for key, stats in per_source.items():
        if stats["attempts"] >= MIN_ATTEMPTS_TO_SHOW:
            rows.append((key[0], key[1], stats))
    rows.sort(key=lambda row: row[2]["attempts"], reverse=True)
    print(f"{'source':<16} {'window':>6} {'attempts':>8} {'ports':>6} "f"{'dsts':>5} {'att/port':>9}  hint")
    shown = 0
    for source, window_index, stats in rows:
        if shown >= MAX_ROWS_PER_FILE:
            break
        attempts = stats["attempts"]
        port_count = len(stats["ports"])
        destination_count = len(stats["destinations"])
        attempts_per_port = attempts / port_count
        hint = behavior_hint(attempts, port_count)
        print(f"{source:<16} {window_index:>6} {attempts:>8} {port_count:>6} "f"{destination_count:>5} {attempts_per_port:>9.2f}  {hint}")
        shown = shown + 1
    if len(rows) == 0:
        print(f"(no source with at least {MIN_ATTEMPTS_TO_SHOW} attempts in a window)")

def print_multi_source_windows(per_destination):
    print()
    print(f"Windows where >= {MULTI_SOURCE_MIN_SOURCES} sources hit the same destination:")
    found = 0
    for key, sources in per_destination.items():
        if len(sources) >= MULTI_SOURCE_MIN_SOURCES:
            sorted_sources = sorted(sources)
            print(f"  dst={key[0]} window={key[1]} sources={', '.join(sorted_sources)}")
            found = found + 1
    if found == 0:
        print("  none")

def main():
    if len(sys.argv) < 2:
        print("Usage: venv/bin/python window_profile.py file1.pcap [file2.pcap ...]")
        return
    for path in sys.argv[1:]:
        print()
        print(f"{path}  (window = {WINDOW_SECONDS}s, only TCP SYN without ACK)")
        try:
            per_source, per_destination = read_attempts(path)
        except FileNotFoundError:
            print(f"[!] File not found: {path}")
            continue
        print_source_table(per_source)
        print_multi_source_windows(per_destination)

if __name__ == "__main__":
    main()