import os
from collections import defaultdict
import pytest
from scapy.all import rdpcap
from features import compute_rich_features, flow_key, get_ips_ports

LO_CAPTURE = "dos.pcap"
DIFF_IP_CAPTURE = "scan.pcap"

def load_flows(path):
    packets = rdpcap(path)
    flows = defaultdict(list)
    for packet in packets:
        info = get_ips_ports(packet)
        if info is not None:
            flows[flow_key(info)].append(packet)
    return list(flows.values())

def totals(path):
    forward_total = 0
    backward_total = 0
    for flow_packets in load_flows(path):
        features = compute_rich_features(flow_packets)
        forward_total = forward_total + features["total_fwd_packets"]
        backward_total = backward_total + features["total_bwd_packets"]
    return forward_total, backward_total

@pytest.mark.skipif(not os.path.exists(LO_CAPTURE), reason="dos.pcap not present")
def test_same_ip_capture_counts_backward():
    forward_total, backward_total = totals(LO_CAPTURE)
    assert backward_total > 0
    assert forward_total > 0

@pytest.mark.skipif(not os.path.exists(DIFF_IP_CAPTURE), reason="scan.pcap not present")
def test_different_ip_capture_still_forward_heavy():
    forward_total, backward_total = totals(DIFF_IP_CAPTURE)
    assert forward_total > backward_total