from scapy.all import sniff, wrpcap

INTERFACE = "eth1"
ROUTER_IP = "192.168.1.1"
CAPTURE_SECONDS = 90
OUTPUT_PATH = "decoy.pcap"

def main():
    capture_filter = f"tcp and host {ROUTER_IP}"
    print(f"Capturing on {INTERFACE} for {CAPTURE_SECONDS}s, filter: {capture_filter}")
    print("Start the nmap decoy scan now in another terminal.")
    packets = sniff(iface=INTERFACE, filter=capture_filter, timeout=CAPTURE_SECONDS)
    wrpcap(OUTPUT_PATH, packets)
    print(f"Saved {len(packets)} packets to {OUTPUT_PATH}")

if __name__ == "__main__":
    main()