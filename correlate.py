import json
from datetime import datetime

alerts = []
with open("alerts.jsonl") as f:
    for line in f:
        alerts.append(json.loads(line))

for a in alerts:
    a["dt"] = datetime.fromisoformat(a["timestamp"])
alerts.sort(key=lambda a: a["dt"])

CORRELATION_WINDOW = 60
incidents = []
for alert in alerts:
    placed = False
    for inc in incidents:
        same_target = (alert["destination"] == inc["destination"])
        within_time = (alert["dt"] - inc["last_seen"]).total_seconds() <= CORRELATION_WINDOW
        if same_target and within_time:
            inc["alerts"].append(alert)
            inc["sources"].add(alert["source"])
            inc["kinds"].add(alert["kind"])
            inc["last_seen"] = alert["dt"]
            inc["total_ports"] = max(inc["total_ports"], alert.get("num_ports", 0))
            placed = True
            break
    if not placed:
        incidents.append({"destination": alert["destination"], "sources": {alert["source"]}, "kinds": {alert["kind"]}, "first_seen": alert["dt"], "last_seen": alert["dt"], "alerts": [alert], "total_ports": alert.get("num_ports", 0),})
print(f"{len(alerts)} raw alerts correlated into {len(incidents)} incidents\n")
print("\n")
for i, inc in enumerate(incidents, 1):
    duration = (inc["last_seen"] - inc["first_seen"]).total_seconds()
    kinds = ", ".join(sorted(inc["kinds"]))
    n_sources = len(inc["sources"])
    n_alerts = len(inc["alerts"])
    print(f"\nINCIDENT #{i}")
    print(f"    Target: {inc['destination']}")
    print(f"    Type: {kinds}")
    print(f"    Sources: {n_sources} ({'distributed/decoy' if n_sources > 2 else 'single'})")
    print(f"    Alerts: {n_alerts} correlated")
    print(f"    Max ports: {inc['total_ports']}")
    print(f"    Time: {inc['first_seen'].strftime('%H:%M:%S')} - {inc['last_seen'].strftime('%H:%M:%S')} ({duration:.0f}s)")
    if n_sources > 2:
        severity = "HIGH (distributed attack)"
    elif "dos" in inc["kinds"]:
        severity = "HIGH (denial of service)"
    elif inc["total_ports"] > 100:
        severity = "MEDIUM (large scan)"
    else:
        severity = "LOW"
    print(f"    Severity: {severity}")