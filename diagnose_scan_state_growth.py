import time
import flow_state

FLOW_COUNTS = [500, 1000, 2000, 4000, 8000]
BASE_SOURCE = "192.168.1.236"
BASE_TARGET = "192.168.1.1"
WINDOW_TIME = 1000.0

def time_slow_scan(flow_count):
    flow_state.reset_scan_state()
    started = time.perf_counter()
    port = 0
    while port < flow_count:
        flow_state.check_slow_scan(BASE_SOURCE, BASE_TARGET, port, WINDOW_TIME)
        port = port + 1
    return time.perf_counter() - started

def time_dest_scan(flow_count):
    flow_state.reset_scan_state()
    started = time.perf_counter()
    port = 0
    while port < flow_count:
        flow_state.check_dest_scan(BASE_TARGET, port, WINDOW_TIME)
        port = port + 1
    return time.perf_counter() - started

def print_growth(title, timing_function):
    print("")
    print(title)
    print("  flows      time(s)   ratio vs previous")
    previous_seconds = None
    for flow_count in FLOW_COUNTS:
        seconds = timing_function(flow_count)
        if previous_seconds is None:
            ratio_text = "-"
        else:
            ratio = seconds / previous_seconds
            ratio_text = str(round(ratio, 2)) + "x"
        print("  " + str(flow_count).rjust(6) + str(round(seconds, 4)).rjust(12) + ratio_text.rjust(12))
        previous_seconds = seconds
    print("  (linear -> about 2.0x per doubling, quadratic -> about 4.0x)")

def main():
    print_growth("check_slow_scan", time_slow_scan)
    print_growth("check_dest_scan", time_dest_scan)

main()