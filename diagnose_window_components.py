import sys
import time
from collections import defaultdict
import live_ids
import flow_state
import trackers
import alert_policy
from features import get_ips_ports, flow_key
from scapy.all import rdpcap

WINDOW_SECONDS = 5
timings = defaultdict(float)
call_counts = defaultdict(int)

PARENT_COMPONENTS = ["live_ids.collect_window_alerts"]

def print_table(total_seconds):
    print("")
    print("component                          time(s)   calls    share")
    names = sorted(timings.keys(), key=lambda name: timings[name], reverse=True)
    accounted = 0.0
    for name in names:
        if name in PARENT_COMPONENTS:
            continue
        seconds = timings[name]
        accounted = accounted + seconds
        share = 100.0 * seconds / total_seconds
        print(name.ljust(34) + str(round(seconds, 2)).rjust(8) + str(call_counts[name]).rjust(8) + (str(round(share, 1)) + "%").rjust(9))
    for name in PARENT_COMPONENTS:
        if name not in timings:
            continue
        parent_seconds = timings[name]
        own_seconds = parent_seconds - accounted
        print((name + " (own)").ljust(34) + str(round(own_seconds, 2)).rjust(8))
    print("accounted".ljust(34) + str(round(accounted, 2)).rjust(8))
    unaccounted = total_seconds - accounted
    print("unaccounted".ljust(34) + str(round(unaccounted, 2)).rjust(8))
    print("TOTAL".ljust(34) + str(round(total_seconds, 2)).rjust(8))

def timed(name, function):
    def wrapper(*args, **kwargs):
        started = time.perf_counter()
        result = function(*args, **kwargs)
        elapsed = time.perf_counter() - started
        timings[name] = timings[name] + elapsed
        call_counts[name] = call_counts[name] + 1
        return result
    return wrapper

def install_timers():
    flow_state.check_slow_scan = timed("flow_state.check_slow_scan", flow_state.check_slow_scan)
    flow_state.check_dest_scan = timed("flow_state.check_dest_scan", flow_state.check_dest_scan)
    trackers.fragment_alerts = timed("trackers.fragment_alerts", trackers.fragment_alerts)
    trackers.icmp_flood_alerts = timed("trackers.icmp_flood_alerts", trackers.icmp_flood_alerts)
    trackers.held_open_connections = timed("trackers.held_open_connections", trackers.held_open_connections)
    live_ids.report_stealth_scans = timed("live_ids.report_stealth_scans", live_ids.report_stealth_scans)
    live_ids.report_ack_scans = timed("live_ids.report_ack_scans", live_ids.report_ack_scans)
    live_ids.slowloris_flow_summaries = timed("live_ids.slowloris_flow_summaries", live_ids.slowloris_flow_summaries)
    live_ids.prepare_window_flows = timed("live_ids.prepare_window_flows", live_ids.prepare_window_flows)
    live_ids.predict_window = timed("live_ids.predict_window", live_ids.predict_window)
    import packet_view
    packet_view.build_views = timed("packet_view.build_views", packet_view.build_views)
    live_ids.collect_window_alerts = timed("live_ids.collect_window_alerts", live_ids.collect_window_alerts)
    alert_policy.flush_window_alerts = timed("alert_policy.flush_window_alerts", alert_policy.flush_window_alerts)

def split_into_windows(packets):
    windows = []
    current = []
    window_start = None
    for pkt in packets:
        packet_time = float(pkt.time)
        if window_start is None:
            window_start = packet_time
        if packet_time - window_start >= WINDOW_SECONDS:
            windows.append(current)
            current = []
            window_start = packet_time
        current.append(pkt)
    if len(current) > 0:
        windows.append(current)
    return windows

def count_flows(packets):
    flows = defaultdict(list)
    for pkt in packets:
        info = get_ips_ports(pkt)
        if info is not None:
            flows[flow_key(info)].append(pkt)
    return len(flows)

def main():
    if len(sys.argv) < 2:
        print("usage: venv/bin/python diagnose_window_components.py capture.pcap")
        return
    capture_path = sys.argv[1]
    live_ids.load_models()
    install_timers()
    live_ids.reset_live_state()
    packets = rdpcap(capture_path)
    windows = split_into_windows(packets)
    print("")
    print("capture: " + capture_path)
    print("packets: " + str(len(packets)) + "  windows: " + str(len(windows)))
    started = time.perf_counter()
    for window_packets in windows:
        live_ids.analyze_window(window_packets)
    total_seconds = time.perf_counter() - started
    print_table(total_seconds)
main()