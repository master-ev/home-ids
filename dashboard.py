import json
from datetime import datetime
from collections import Counter

alerts = []
try:
    with open("alerts.jsonl") as f:
        for line in f:
            alerts.append(json.loads(line))
except FileNotFoundError:
    print("No alerts.jsonl found")
    alerts = []

total = len(alerts)
by_kind = Counter(a["kind"] for a in alerts)
by_source = Counter(a["source"] for a in alerts)
by_day = Counter(a["timestamp"][:10] for a in alerts)

colors = {"port_scan": "#a855f7", "brute_force": "#ef4444", "suspicious": "#eab308"}

html = []
html.append("<!DOCTYPE html><html><head><meta charset='utf-8'>")
html.append("<title>Home IDS Dashboard</title>")
html.append("<link href='https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&display=swap' rel='stylesheet'>")
html.append("<style>")
html.append("* { box-sizing: border-box; margin: 0; }")
html.append("body { font-family: 'Space Grotesk', sans-serif; background: radial-gradient(circle at 20% 0%, #1a0b2e 0%, #0a0a0f 55%), linear-gradient(135deg, #0d1f14 0%, #0a0a0f 60%); background-blend-mode: screen; color: #f0f0f5; padding: 40px; min-height: 100vh; }")
html.append("h1 { font-size: 34px; font-weight: 700; background: linear-gradient(90deg, #a855f7, #22e06b); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }")
html.append("h2 { font-size: 18px; margin-bottom: 12px; }")
html.append(".sub { color: #8a8aa0; margin-bottom: 20px; font-size: 13px; }")
html.append(".card { background: rgba(255,255,255,0.03); border: 1px solid #2a2a3a; border-radius: 12px; padding: 16px 22px; }")
html.append(".card .num { font-size: 28px; font-weight: 700; }")
html.append(".card .label { color: #8a8aa0; font-size: 12px; }")
html.append("table { width: 100%; border-collapse: collapse; }")
html.append("th { text-align: left; color: #8a8aa0; font-size: 13px; padding: 10px; border-bottom: 1px solid #2a2a3a; }")
html.append("td { padding: 10px; border-bottom: 1px solid #1a1a26; font-size: 14px; }")
html.append(".tag { padding: 3px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; }")
html.append(".port_scan { background: rgba(168,85,247,0.2); color: #c896ff; }")
html.append(".brute_force { background: rgba(239,68,68,0.2); color: #ff8888; }")
html.append(".suspicious { background: rgba(234,179,8,0.2); color: #ffd93d; }")
html.append("</style></head><body>")

html.append("<div style='display:flex; gap:40px; align-items:flex-start; margin-bottom:40px;'>")

html.append("<div style='flex:1;'>")
html.append("<h1>Home IDS Dashboard</h1>")
html.append(f"<div class='sub'>Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>")
html.append("<div style='display:grid; grid-template-columns:1fr 1fr; gap:14px;'>")
html.append(f"<div class='card'><div class='num'>{total}</div><div class='label'>Total alerts</div></div>")
html.append(f"<div class='card'><div class='num'>{by_kind.get('port_scan', 0)}</div><div class='label'>Port scans</div></div>")
html.append(f"<div class='card'><div class='num'>{by_kind.get('brute_force', 0)}</div><div class='label'>Brute force</div></div>")
html.append(f"<div class='card'><div class='num'>{by_kind.get('suspicious', 0)}</div><div class='label'>Suspicious</div></div>")
html.append(f"<div class='card'><div class='num'>{len(by_source)}</div><div class='label'>Unique sources</div></div>")
html.append("</div>")
html.append("</div>")

html.append("<div style='flex:1;'>")
html.append("<h2>Alerts by type</h2>")
html.append("<div style='display:flex; align-items:flex-end; gap:40px; height:170px; margin-bottom:40px;'>")
max_kind = max(by_kind.values()) if by_kind else 1
for kind, count in by_kind.most_common():
    height = int(140 * count / max_kind)
    color = colors.get(kind, "#22e06b")
    html.append(f"<div style='display:flex; flex-direction:column; align-items:center; gap:6px;'><div style='font-weight:600;'>{count}</div><div style='width:60px; height:{height}px; background:{color}; border-radius:8px 8px 0 0;'></div><div style='color:#8a8aa0; font-size:13px;'>{kind}</div></div>")
html.append("</div>")
html.append("<h2>Alerts per day</h2>")
html.append("<div style='display:flex; align-items:flex-end; gap:20px; height:170px;'>")
max_day = max(by_day.values()) if by_day else 1
for day in sorted(by_day.keys()):
    count = by_day[day]
    height = int(140 * count / max_day)
    html.append(f"<div style='display:flex; flex-direction:column; align-items:center; gap:6px;'><div style='font-weight:600;'>{count}</div><div style='width:80px; height:{height}px; background:linear-gradient(180deg,#22e06b,#a855f7); border-radius:8px 8px 0 0;'></div><div style='color:#8a8aa0; font-size:12px;'>{day[5:]}</div></div>")
html.append("</div>")

html.append("</div>")
html.append("</div>")
html.append("<table><tr><th>Time</th><th>Type</th><th>Source</th><th>Destination</th><th>Details</th></tr>")
for a in reversed(alerts):
    t = a["timestamp"][:19].replace("T", " ")
    kind = a["kind"]
    html.append(f"<tr><td>{t}</td><td><span class='tag {kind}'>{kind}</span></td><td>{a['source']}</td><td>{a['destination']}</td><td>{a.get('description','')}</td></tr>")
html.append("</table>")
html.append("</body></html>")
with open("dashboard.html", "w") as f:
    f.write("\n".join(html))
print(f"Wrote dashboard.html with {total} alerts")
