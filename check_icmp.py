from scapy.all import ICMP, IP, Ether
from features import get_ips_ports

def make_icmp_packet(source, destination):
    raw = Ether() / IP(src=source, dst=destination) / ICMP()
    return Ether(bytes(raw))

def main():
    packet = make_icmp_packet("192.168.1.236", "192.168.1.1")
    info = get_ips_ports(packet)
    print(f"get_ips_ports on ICMP: {info}")
    if info is None:
        print("[!] Confirmed: ICMP is ignored by the whole pipeline.")
        print("    An ICMP flood is currently invisible to the IDS.")
    else:
        print("ICMP is parsed. Proto:", info[4])

if __name__ == "__main__":
    main()