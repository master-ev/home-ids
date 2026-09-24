import pytest
from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw
import packet_view
from packet_view import (VIEW_DPORT, VIEW_DST, VIEW_FLAGS, VIEW_PAYLOAD, VIEW_PROTO, VIEW_SPORT, VIEW_SRC, build_view, build_views, tcp_views)
SOURCE = "192.168.1.236"
TARGET = "192.168.1.1"

def make_tcp(sport, dport, flags, payload_bytes):
    packet = IP(src=SOURCE, dst=TARGET) / TCP(sport=sport, dport=dport, flags=flags)
    if payload_bytes > 0:
        packet = packet / Raw(b"x" * payload_bytes)
    return IP(bytes(packet))

def test_tcp_view_matches_scapy():
    packet = make_tcp(4444, 80, "S", 0)
    view = build_view(packet)
    assert view[VIEW_SRC] == packet[IP].src
    assert view[VIEW_DST] == packet[IP].dst
    assert view[VIEW_SPORT] == packet[TCP].sport
    assert view[VIEW_DPORT] == packet[TCP].dport
    assert view[VIEW_FLAGS] == int(packet[TCP].flags)
    assert view[VIEW_PROTO] == packet_view.TCP_PROTO

def test_payload_length_matches_the_raw_bytes():
    packet = make_tcp(4444, 80, "PA", 100)
    view = build_view(packet)
    assert view[VIEW_PAYLOAD] == 100

def test_empty_payload_is_zero_not_none():
    packet = make_tcp(4444, 80, "S", 0)
    view = build_view(packet)
    assert view[VIEW_PAYLOAD] == 0

def test_udp_view_has_ports_but_no_flags():
    packet = IP(src=SOURCE, dst=TARGET) / UDP(sport=5353, dport=53)
    view = build_view(packet)
    assert view[VIEW_SPORT] == 5353
    assert view[VIEW_DPORT] == 53
    assert view[VIEW_FLAGS] is None
    assert view[VIEW_PROTO] == packet_view.UDP_PROTO

def test_icmp_view_has_no_ports():
    packet = IP(src=SOURCE, dst=TARGET) / ICMP()
    view = build_view(packet)
    assert view[VIEW_SPORT] is None
    assert view[VIEW_DPORT] is None
    assert view[VIEW_PROTO] == packet_view.ICMP_PROTO

def test_packet_without_ip_gives_none():
    packet = Ether()
    assert build_view(packet) is None

def test_views_stay_aligned_with_packets():
    packets = [make_tcp(1, 80, "S", 0), Ether(), make_tcp(2, 443, "A", 5)]
    views = build_views(packets)
    assert len(views) == len(packets)
    assert views[1] is None
    assert views[2][VIEW_DPORT] == 443

def test_tcp_views_drops_everything_else():
    packets = [make_tcp(1, 80, "S", 0), IP(src=SOURCE, dst=TARGET) / UDP(sport=1, dport=53), IP(src=SOURCE, dst=TARGET) / ICMP()]
    selected = tcp_views(build_views(packets))
    assert len(selected) == 1

def test_stealth_flags_survive_the_round_trip():
    null_view = build_view(make_tcp(1, 80, 0, 0))
    fin_view = build_view(make_tcp(1, 80, "F", 0))
    xmas_view = build_view(make_tcp(1, 80, "FPU", 0))
    assert null_view[VIEW_FLAGS] == 0
    assert fin_view[VIEW_FLAGS] == 0x01
    assert xmas_view[VIEW_FLAGS] == 0x29