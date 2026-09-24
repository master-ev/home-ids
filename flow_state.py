from collections import Counter, defaultdict, deque

SLOW_SCAN_WINDOW_SECONDS = 300
SLOW_SCAN_THRESHOLD = 15
DEST_SCAN_WINDOW_SECONDS = 300
DEST_SCAN_THRESHOLD = 20
slow_scan_history = defaultdict(deque)
slow_scan_port_counts = defaultdict(Counter)
slow_scan_alerted = set()
dest_scan_history = defaultdict(deque)
dest_scan_port_counts = defaultdict(Counter)
dest_scan_alerted = set()

def reset_scan_state():
    slow_scan_history.clear()
    slow_scan_port_counts.clear()
    slow_scan_alerted.clear()
    dest_scan_history.clear()
    dest_scan_port_counts.clear()
    dest_scan_alerted.clear()

def add_entry(history, port_counts, window_time, port):
    history.append((window_time, port))
    port_counts[port] = port_counts[port] + 1

def expire_old_entries(history, port_counts, cutoff_time):
    while len(history) > 0:
        oldest_time, oldest_port = history[0]
        if oldest_time > cutoff_time:
            break
        history.popleft()
        port_counts[oldest_port] = port_counts[oldest_port] - 1
        if port_counts[oldest_port] == 0:
            del port_counts[oldest_port]

def check_slow_scan(source, destination, port, window_time):
    pair = (source, destination)
    history = slow_scan_history[pair]
    port_counts = slow_scan_port_counts[pair]
    add_entry(history, port_counts, window_time, port)
    cutoff_time = window_time - SLOW_SCAN_WINDOW_SECONDS
    expire_old_entries(history, port_counts, cutoff_time)
    distinct_ports = len(port_counts)
    if distinct_ports < SLOW_SCAN_THRESHOLD:
        slow_scan_alerted.discard(pair)
        return None
    if pair in slow_scan_alerted:
        return None
    slow_scan_alerted.add(pair)
    return distinct_ports

def check_dest_scan(destination, port, window_time):
    history = dest_scan_history[destination]
    port_counts = dest_scan_port_counts[destination]
    add_entry(history, port_counts, window_time, port)
    cutoff_time = window_time - DEST_SCAN_WINDOW_SECONDS
    expire_old_entries(history, port_counts, cutoff_time)
    distinct_ports = len(port_counts)
    if distinct_ports < DEST_SCAN_THRESHOLD:
        dest_scan_alerted.discard(destination)
        return None
    if destination in dest_scan_alerted:
        return None
    dest_scan_alerted.add(destination)
    return distinct_ports