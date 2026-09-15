from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, conf
from collections import Counter

conf.use_pcap = True

protocols = Counter()
dst_ports = Counter()
captured = []

def process(packet):
    captured.append(packet)
    has_ip = IP in packet or IPv6 in packet
    if not has_ip:
        protocols["non-IP"] += 1
        return
    if TCP in packet:
        protocols["TCP"] += 1
        dst_ports[packet[TCP].dport] += 1
    elif UDP in packet:
        protocols["UDP"] += 1
        dst_ports[packet[UDP].dport] += 1
    else:
        protocols["other-IP"] += 1

print("Capturing for 300 seconds...")
sniff(iface="eth1", prn=process, filter="tcp or udp", timeout=300)
# wrpcap("capture.pcap", captured)
# wrpcap("scan.pcap", captured)
# wrpcap("normal.pcap", captured)
# wrpcap("bruteforce.pcap", captured)
wrpcap("normal_rich.pcap", captured)
print("\nSaved capture.pcap")
print("\nProtocol breakdown:")
for proto, count in protocols.most_common():
    print(f"    {proto:10} {count}")
print("\n Top destination ports:")
for port, count in dst_ports.most_common(10):
    print(f"    port {port:6} {count}")