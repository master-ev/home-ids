from scapy.all import IP, TCP, Ether
from context import compute_context
from features import compute_rich_features

ATTACKER = "192.168.1.244"
TARGET = "192.168.1.1"
TARGET_PORT = 80
FLOOD_FLOWS = 40
FIRST_SRC_PORT = 30000

def make_syn(source_port):
    raw = Ether() / IP(src=ATTACKER, dst=TARGET) / TCP(
        sport=source_port, dport=TARGET_PORT, flags="S")
    return Ether(bytes(raw))

def main():
    flow_list = []
    index = 0
    while index < FLOOD_FLOWS:
        flow_list.append([make_syn(FIRST_SRC_PORT + index)])
        index = index + 1
    context_rows = compute_context(flow_list)
    print("SYN flood simulated flows (per-window context):")
    sample = context_rows[0]
    for name, value in sample.items():
        print(f"  {name:22} {value}")
    print()
    print("A SYN flood should look like:")
    print("  many flows, ctx_src_ports = 1 (one dest port), reply_rate = 0,")
    print("  syn_count = 1 per flow, is_tcp = 1")
    features = compute_rich_features(flow_list[0])
    print()
    print("Per-flow features of one SYN:")
    for name in ["syn_count", "is_tcp", "total_fwd_packets", "total_bwd_packets"]:
        print(f"  {name:22} {features.get(name)}")

if __name__ == "__main__":
    main()