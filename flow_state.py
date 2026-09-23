from collections import defaultdict

SLOW_SCAN_WINDOW = 300
SLOW_SCAN_THRESHOLD = 15
DEST_SCAN_THRESHOLD = 20
port_history = defaultdict(list)
dest_history = defaultdict(list)
slow_scan_alerted = set()
dest_scan_alerted = set()

def check_slow_scan(src, dst, dport, now):
    key = (src, dst)
    port_history[key].append((dport, now))
    port_history[key] = [(p, t) for (p, t) in port_history[key] if now - t < SLOW_SCAN_WINDOW]
    distinct_ports = len(set(p for (p, t) in port_history[key]))
    if distinct_ports < SLOW_SCAN_THRESHOLD:
        slow_scan_alerted.discard(key)
        return None
    if key in slow_scan_alerted:
        return None
    slow_scan_alerted.add(key)
    return distinct_ports

def check_dest_scan(dst, dport, now):
    dest_history[dst].append((dport, now))
    dest_history[dst] = [(p, t) for (p, t) in dest_history[dst] if now - t < SLOW_SCAN_WINDOW]
    distinct_ports = len(set(p for (p, t) in dest_history[dst]))
    if distinct_ports < DEST_SCAN_THRESHOLD:
        dest_scan_alerted.discard(dst)
        return None
    if dst in dest_scan_alerted:
        return None
    dest_scan_alerted.add(dst)
    return distinct_ports

def reset_scan_state():
    port_history.clear()
    slow_scan_alerted.clear()
    dest_history.clear()
    dest_scan_alerted.clear()