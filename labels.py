SCAN_MIN_PORTS = 10
MIN_ATTACK_FLOWS = 10
FEW_PORTS_MAX = 3
SUSPICIOUS_MIN_FLOWS = 5
DOS_VERDICT = "dos"
SCAN_VERDICT = "scan"
ANOMALY_VERDICT = "anomaly"
FLOOD_MIN_FLOWS_PER_PORT = 5
SCAN_MAX_FLOWS_PER_PORT = 3

def flows_per_port(num_flows, num_ports):
    if num_ports == 0:
        return 0.0
    return num_flows / num_ports

def choose_campaign_label(main_verdict, num_flows, num_ports):
    ratio = flows_per_port(num_flows, num_ports)
    looks_like_flood = ratio >= FLOOD_MIN_FLOWS_PER_PORT
    looks_like_scan = ratio <= SCAN_MAX_FLOWS_PER_PORT
    few_ports = num_ports <= FEW_PORTS_MAX
    enough_attack_flows = num_flows > MIN_ATTACK_FLOWS
    enough_suspicious_flows = num_flows >= SUSPICIOUS_MIN_FLOWS
    if main_verdict == ANOMALY_VERDICT and enough_suspicious_flows:
        return "anomaly", f"ANOMALY ({num_flows} unusual flows, {num_ports} ports)"
    if main_verdict == "udp_scan" and enough_suspicious_flows:
        return "udp_scan", f"UDP SCAN({num_ports} ports)"
    if main_verdict == "syn_flood" and enough_attack_flows and few_ports:
        return "syn_flood", f"SYN FLOOD ({num_flows} half-open)"
    if main_verdict == DOS_VERDICT and enough_attack_flows:
        if few_ports or looks_like_flood:
            return "dos", f"DoS FLOOD ({num_flows} flows)"
    if main_verdict == SCAN_VERDICT and enough_suspicious_flows and looks_like_scan:
        return "port_scan", f"PORT SCAN({num_ports} ports)"
    if num_ports >= SCAN_MIN_PORTS:
        return "port_scan", f"PORT SCAN({num_ports} ports)"
    if enough_attack_flows and few_ports:
        return "brute_force", f"BRUTE FORCE ({num_flows} attempts)"
    if enough_suspicious_flows:
        return "suspicious", f"{num_flows} suspicious flows"
    return None, None