from scapy.all import sniff, wrpcap, conf
conf.use_pcap = True
print("Capturing brute-force traffic on lo")
packets = sniff(iface="lo", filter="port 8000", timeout=40)
wrpcap("bruteforce.pcap", packets)
print(f"Saved bruteforce.pcap with {len(packets)} packets")