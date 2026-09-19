from scapy.all import sniff, IP, TCP, UDP, conf

conf.use_pcap = True

def describe(packet):
    if IP not in packet:
        return
    source = packet[IP].src
    destination = packet[IP].dst
    protocol = "OTHER"
    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
    else:
        source_port = 0
        destination_port = 0
    print(f"{protocol:5} {source}:{source_port} -> {destination}:{destination_port} ({len(packet)} bytes)")

sniff(iface="eth1", count=20, prn=describe)