import sys
from scapy.all import rdpcap, IP, TCP
from trackers import classify_stealth_flags

def count_stealth(pcap_path):
    packets = rdpcap(pcap_path)
    total_tcp = 0
    type_counts = {}
    source_counts = {}
    for pkt in packets:
        has_ip = IP in pkt
        has_tcp = TCP in pkt
        if not (has_ip and has_tcp):
            continue
        total_tcp = total_tcp + 1
        flags = int(pkt[TCP].flags)
        scan_type = classify_stealth_flags(flags)
        if scan_type is None:
            continue
        if scan_type not in type_counts:
            type_counts[scan_type] = 0
        type_counts[scan_type] = type_counts[scan_type] + 1
        src = pkt[IP].src
        if src not in source_counts:
            source_counts[src] = 0
        source_counts[src] = source_counts[src] + 1
    print(pcap_path)
    print("TCP packets total: " + str(total_tcp))
    if len(type_counts) == 0:
        print("No stealth packets found.")
    for scan_type in sorted(type_counts):
        print("  " + scan_type + ": " + str(type_counts[scan_type]))
    for src in sorted(source_counts):
        print("  from " + src + ": " + str(source_counts[src]))
    print()

def main():
    if len(sys.argv) < 2:
        print("Usage: venv/bin/python check_stealth.py file1.pcap [file2.pcap ...]")
        return
    for pcap_path in sys.argv[1:]:
        count_stealth(pcap_path)

if __name__ == "__main__":
    main()