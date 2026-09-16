import sys
from scapy.all import sniff, wrpcap

DEFAULT_FILTER = "tcp"
MIN_ARGUMENTS = 4

def main():
    if len(sys.argv) < MIN_ARGUMENTS:
        print("Usage: sudo venv/bin/python capture_scenario.py IFACE SECONDS OUTPUT [filter...]")
        return
    interface = sys.argv[1]
    seconds = int(sys.argv[2])
    output_path = sys.argv[3]
    capture_filter = DEFAULT_FILTER
    if len(sys.argv) > MIN_ARGUMENTS:
        capture_filter = " ".join(sys.argv[MIN_ARGUMENTS:])
    print(f"Capturing on {interface} for {seconds}s, filter: '{capture_filter}'")
    print("Start the traffic NOW in the other terminal.")
    packets = sniff(iface=interface, filter=capture_filter, timeout=seconds)
    wrpcap(output_path, packets)
    print(f"Saved {len(packets)} packets to {output_path}")

if __name__ == "__main__":
    main()