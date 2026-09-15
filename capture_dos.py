from scapy.all import sniff, wrpcap, conf
conf.use_pcap = True

print("Capturing DoS traffic on lo (port 8000)")
packets = sniff(iface="lo", filter="port 8000", timeout=30)
wrpcap("dos.pcap", packets)
print(f"Saved dos.pcap with {len(packets)} packets")