from scapy.all import conf

def read_drop_stats(sniffer):
    socket = getattr(sniffer, "L2socket", None)
    if socket is None:
        return (None, None)
    inner = getattr(socket, "ins", None)
    if inner is None:
        return (None, None)
    stats_function = getattr(inner, "stats", None)
    if stats_function is None:
        return (None, None)
    stats = stats_function()
    received = stats[0]
    dropped = stats[1]
    return (received, dropped)

def format_drop_report(received, dropped):
    if received is None:
        return "capture stats not available on this platform"
    total = received + dropped
    if total == 0:
        loss_percent = 0.0
    else:
        loss_percent = 100.0 * dropped / total
    line = ("captured " + str(received) + ", dropped " + str(dropped) + " (" + str(round(loss_percent, 2)) + "% loss)")
    return line