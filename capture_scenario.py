import sys
from scapy.all import TCP, UDP, sniff, wrpcap

DEFAULT_FILTER = "tcp"
MIN_ARGUMENTS = 4
PORT_OPTION = "--port"
NO_PORT = 0

def packet_has_port(packet, port):
    if packet.haslayer(TCP):
        if packet[TCP].sport == port or packet[TCP].dport == port:
            return True
    if packet.haslayer(UDP):
        if packet[UDP].sport == port or packet[UDP].dport == port:
            return True
    return False

def capture_with_python_filter(interface, seconds, port):
    print(f"Capturing on {interface} for {seconds}s, Python filter: port {port}")
    print("Start the traffic NOW in the other terminal.")
    all_packets = sniff(iface=interface, timeout=seconds)
    kept = []
    for packet in all_packets:
        if packet_has_port(packet, port):
            kept.append(packet)
    print(f"Sniffed {len(all_packets)} packets, kept {len(kept)} on port {port}")
    return kept

def capture_with_bpf(interface, seconds, capture_filter):
    print(f"Capturing on {interface} for {seconds}s, BPF filter: '{capture_filter}'")
    print("Start the traffic NOW in the other terminal.")
    return sniff(iface=interface, filter=capture_filter, timeout=seconds)

def main():
    if len(sys.argv) < MIN_ARGUMENTS:
        print("Usage: sudo venv/bin/python capture_scenario.py IFACE SECONDS OUTPUT [filter...]")
        print("   or: sudo venv/bin/python capture_scenario.py lo SECONDS OUTPUT --port 8000")
        return
    interface = sys.argv[1]
    seconds = int(sys.argv[2])
    output_path = sys.argv[3]
    use_port = NO_PORT
    if len(sys.argv) > MIN_ARGUMENTS and sys.argv[MIN_ARGUMENTS] == PORT_OPTION:
        use_port = int(sys.argv[MIN_ARGUMENTS + 1])
    if use_port != NO_PORT:
        packets = capture_with_python_filter(interface, seconds, use_port)
    else:
        capture_filter = DEFAULT_FILTER
        if len(sys.argv) > MIN_ARGUMENTS:
            capture_filter = " ".join(sys.argv[MIN_ARGUMENTS:])
        packets = capture_with_bpf(interface, seconds, capture_filter)
    if len(packets) == 0:
        print("[!] 0 packets. Traffic started before capture, or wrong interface?")
        return
    wrpcap(output_path, packets)
    print(f"Saved {len(packets)} packets to {output_path}")

if __name__ == "__main__":
    main()