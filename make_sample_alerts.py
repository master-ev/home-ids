import json
from datetime import datetime, timedelta

OUTPUT_PATH = "sample_alerts.jsonl"
BASE_HOUR = 10
TODAY_OFFSET = 0
YESTERDAY_OFFSET = -1
ROUTER = "192.168.1.1"
WEB_SERVER = "192.168.1.10"
NAS = "192.168.1.20"

SCENARIOS = [
    {"src": "192.168.1.50", "dst": ROUTER, "type": "scan", "count": 4,
     "interval": 30, "day": YESTERDAY_OFFSET, "start": 0},
    {"src": "192.168.1.50", "dst": ROUTER, "type": "scan", "count": 2,
     "interval": 30, "day": YESTERDAY_OFFSET, "start": 1200},
    {"src": "10.0.0.7", "dst": ROUTER, "type": "anomaly", "count": 1,
     "interval": 0, "day": YESTERDAY_OFFSET, "start": 10800},
    {"src": "192.168.1.66", "dst": WEB_SERVER, "type": "bruteforce", "count": 6,
     "interval": 10, "day": TODAY_OFFSET, "start": 0},
    {"src": "192.168.1.77", "dst": WEB_SERVER, "type": "bruteforce", "count": 2,
     "interval": 10, "day": TODAY_OFFSET, "start": 1800},
    {"src": "192.168.1.99", "dst": WEB_SERVER, "type": "dos", "count": 8,
     "interval": 5, "day": TODAY_OFFSET, "start": 3600},
    {"src": "192.168.1.88", "dst": ROUTER, "type": "slow_scan", "count": 1,
     "interval": 0, "day": TODAY_OFFSET, "start": 7200},
    # decoy scan
    {"src": "10.0.0.11", "dst": NAS, "type": "scan", "count": 1,
     "interval": 0, "day": TODAY_OFFSET, "start": 14400},
    {"src": "10.0.0.12", "dst": NAS, "type": "scan", "count": 1,
     "interval": 0, "day": TODAY_OFFSET, "start": 14400},
    {"src": "10.0.0.13", "dst": NAS, "type": "scan", "count": 1,
     "interval": 0, "day": TODAY_OFFSET, "start": 14400},
    {"src": "192.168.1.40", "dst": NAS, "type": "scan", "count": 1,
     "interval": 0, "day": TODAY_OFFSET, "start": 14400},
    # multi-stage
    {"src": "192.168.1.30", "dst": NAS, "type": "scan", "count": 3,
     "interval": 20, "day": TODAY_OFFSET, "start": 18000},
    {"src": "192.168.1.30", "dst": NAS, "type": "bruteforce", "count": 3,
     "interval": 10, "day": TODAY_OFFSET, "start": 18060},
]

def main():
    now = datetime.now()
    base = now.replace(hour=BASE_HOUR, minute=0, second=0, microsecond=0)
    lines = []
    scenario_index = 0
    while scenario_index < len(SCENARIOS):
        scenario = SCENARIOS[scenario_index]
        day_start = base + timedelta(days=scenario["day"])
        scenario_start = day_start + timedelta(seconds=scenario["start"])
        alert_index = 0
        while alert_index < scenario["count"]:
            offset_seconds = alert_index * scenario["interval"]
            moment = scenario_start + timedelta(seconds=offset_seconds)
            alert = {"timestamp": moment.isoformat(), "source": scenario["src"], "destination": scenario["dst"], "kind": scenario["type"],}
            lines.append(json.dumps(alert))
            alert_index = alert_index + 1
        scenario_index = scenario_index + 1
    file = open(OUTPUT_PATH, "w")
    line_index = 0
    while line_index < len(lines):
        file.write(lines[line_index] + "\n")
        line_index = line_index + 1
    file.close()
    print(f"Wrote {len(lines)} sample alerts to {OUTPUT_PATH}")

if __name__ == "__main__":
    main()