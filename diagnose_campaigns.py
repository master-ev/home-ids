import sys
from collections import defaultdict
from scapy.all import rdpcap
import live_ids
from features import get_ips_ports, flow_key
from replay import split_into_windows

EPHEMERAL_PORT_MIN = 32768
MAX_PORTS_SHOWN = 10
TRACKER_KINDS = ["slow_scan", "distributed_scan", "fragmented_scan", "icmp_flood", "slowloris", "stealth_scan"]
window_alerts = []

def recording_log_alert(alert):
    window_alerts.append(alert)

def ports_by_pair(window):
    flows = defaultdict(list)
    for p in window:
        info = get_ips_ports(p)
        if info is not None:
            flows[flow_key(info)].append(p)
    pair_ports = defaultdict(set)
    for key in flows:
        pkts = flows[key]
        info = get_ips_ports(pkts[0])
        src = info[0]
        dst = info[1]
        dport = info[3]
        pair_ports[(src, dst)].add(dport)
    return pair_ports

def flows_per_port_text(num_flows, num_ports):
    if num_ports == 0:
        return "-"
    ratio = num_flows / num_ports
    return f"{ratio:.1f}"

def print_alert(window_index, alert, pair_ports):
    src = alert["source"]
    dst = alert["destination"]
    pair = (src, dst)
    ports = sorted(pair_ports.get(pair, set()))
    ephemeral = 0
    for port in ports:
        if port is not None and port >= EPHEMERAL_PORT_MIN:
            ephemeral = ephemeral + 1
    num_flows = alert["num_flows"]
    num_ports = alert["num_ports"]
    ratio_text = flows_per_port_text(num_flows, num_ports)
    sample = ports[:MAX_PORTS_SHOWN]
    print(f"  window {window_index}: {src} -> {dst}")
    print(f"     kind={alert['kind']}  verdict={alert['model_verdict']}  conf={alert['confidence']}")
    print(f"     flows={num_flows}  ports={num_ports}  flows/port={ratio_text}  ephemeral={ephemeral}/{len(ports)}")
    print(f"     port sample={sample}")

def diagnose(path):
    print()
    print(path)
    live_ids.reset_live_state()
    packets = rdpcap(path)
    windows = split_into_windows(packets, live_ids.WINDOW_SECONDS)
    window_index = 0
    for window in windows:
        window_index = window_index + 1
        window_alerts.clear()
        live_ids.analyze_window(window)
        pair_ports = ports_by_pair(window)
        for alert in window_alerts:
            if alert["kind"] in TRACKER_KINDS:
                continue
            print_alert(window_index, alert, pair_ports)

def main():
    if len(sys.argv) < 2:
        print("Usage: venv/bin/python diagnose_campaigns.py capture1.pcap [capture2.pcap ...]")
        return
    live_ids.load_models()
    live_ids.log_alert = recording_log_alert
    for path in sys.argv[1:]:
        diagnose(path)

if __name__ == "__main__":
    main()