import html
import sys
from datetime import datetime
import incidents as inc

DEFAULT_ALERTS_PATH = "alerts.jsonl"
OUTPUT_PATH = "dashboard.html"
TOP_SOURCES_LIMIT = 5
RAW_ALERTS_LIMIT = 50
FULL_WIDTH_PERCENT = 100

CSS = """
:root {
  --bg: #0f1115;
  --panel: #181b22;
  --border: #2a2f3a;
  --text: #e6e8ee;
  --muted: #9aa3b2;
  --green: #3dd68c;
  --purple: #a371f7;
  --high: #ff5c6c;
  --medium: #f5a524;
  --low: #3dd68c;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 24px;
  background: var(--bg);
  color: var(--text);
  font-family: "Segoe UI", Roboto, Arial, sans-serif;
}
h1 { margin: 0 0 4px 0; }
h1 span { color: var(--green); }
h2 { color: var(--purple); margin-top: 32px; }
.subtitle { color: var(--muted); margin-bottom: 24px; }
.cards { display: flex; flex-wrap: wrap; gap: 16px; }
.card {
  flex: 1 1 160px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 16px;
}
.card .label { color: var(--muted); font-size: 13px; }
.card .value { font-size: 32px; font-weight: bold; margin-top: 6px; }
.card.high { border-top: 4px solid var(--high); }
.card.medium { border-top: 4px solid var(--medium); }
.card.low { border-top: 4px solid var(--low); }
.card.total { border-top: 4px solid var(--purple); }
.panel {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 16px;
  overflow-x: auto;
}
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: normal; }
.badge {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: bold;
  color: #0f1115;
}
.badge.HIGH { background: var(--high); }
.badge.MEDIUM { background: var(--medium); }
.badge.LOW { background: var(--low); }
.row { display: flex; align-items: center; gap: 12px; margin: 8px 0; }
.row .name { width: 120px; color: var(--muted); font-size: 13px; }
.row .track { flex: 1; background: #232834; border-radius: 6px; height: 18px; display: flex; overflow: hidden; }
.row .count { width: 40px; text-align: right; }
.seg { height: 100%; }
.seg.HIGH { background: var(--high); }
.seg.MEDIUM { background: var(--medium); }
.seg.LOW { background: var(--low); }
.seg.plain { background: linear-gradient(90deg, var(--green), var(--purple)); }
.legend span { margin-right: 16px; font-size: 13px; color: var(--muted); }
details summary { cursor: pointer; color: var(--purple); margin: 8px 0; }
.empty { color: var(--muted); }
code { color: var(--green); }
"""


def esc(value):
    return html.escape(str(value))

def percent_of(value, maximum):
    if maximum == 0:
        return 0
    return int(value * FULL_WIDTH_PERCENT / maximum)

def build_cards(incident_list, alert_count):
    counts = inc.count_by_severity(incident_list)
    total_incidents = len(incident_list)
    parts = []
    parts.append('<div class="cards">')
    parts.append(f'<div class="card total"><div class="label">Incidents</div>'f'<div class="value">{total_incidents}</div></div>')
    parts.append(f'<div class="card high"><div class="label">HIGH</div>'f'<div class="value">{counts[inc.SEVERITY_HIGH]}</div></div>')
    parts.append(f'<div class="card medium"><div class="label">MEDIUM</div>'f'<div class="value">{counts[inc.SEVERITY_MEDIUM]}</div></div>')
    parts.append(f'<div class="card low"><div class="label">LOW</div>'f'<div class="value">{counts[inc.SEVERITY_LOW]}</div></div>')
    parts.append(f'<div class="card total"><div class="label">Raw alerts</div>'f'<div class="value">{alert_count}</div></div>')
    parts.append('</div>')
    return "\n".join(parts)

def build_incident_table(incident_list):
    if len(incident_list) == 0:
        return '<p class="empty">No incidents.</p>'
    parts = []
    parts.append('<table>')
    parts.append('<tr><th>Severity</th><th>Source</th><th>Type</th>''<th>Alerts</th><th>Start</th><th>End</th><th>Duration</th></tr>')
    index = 0
    while index < len(incident_list):
        incident = incident_list[index]
        severity = incident["severity"]
        start_text = inc.format_time(incident["first_time"])
        end_text = inc.format_time(incident["last_time"])
        duration_text = inc.format_duration(incident["duration"])
        parts.append('<tr>')
        parts.append(f'<td><span class="badge {esc(severity)}">{esc(severity)}</span></td>')
        parts.append(f'<td><code>{esc(incident["src"])}</code></td>')
        parts.append(f'<td>{esc(incident["type"])}</td>')
        parts.append(f'<td>{incident["alert_count"]}</td>')
        parts.append(f'<td>{esc(start_text)}</td>')
        parts.append(f'<td>{esc(end_text)}</td>')
        parts.append(f'<td>{esc(duration_text)}</td>')
        parts.append('</tr>')
        index = index + 1
    parts.append('</table>')
    return "\n".join(parts)

def build_day_chart(incident_list):
    days = inc.count_per_day(incident_list)
    if len(days) == 0:
        return '<p class="empty">No data.</p>'
    day_names = sorted(days.keys())
    max_total = 0
    index = 0
    while index < len(day_names):
        day_counts = days[day_names[index]]
        day_total = (day_counts[inc.SEVERITY_HIGH] + day_counts[inc.SEVERITY_MEDIUM] + day_counts[inc.SEVERITY_LOW])
        if day_total > max_total:
            max_total = day_total
        index = index + 1
    parts = []
    parts.append('<div class="legend"><span>&#9632; HIGH</span>''<span>&#9632; MEDIUM</span><span>&#9632; LOW</span></div>')
    index = 0
    while index < len(day_names):
        day = day_names[index]
        day_counts = days[day]
        day_total = 0
        segments = []
        severity_index = 0
        while severity_index < len(inc.SEVERITY_ORDER):
            severity = inc.SEVERITY_ORDER[severity_index]
            value = day_counts[severity]
            day_total = day_total + value
            width = percent_of(value, max_total)
            if value > 0:
                segments.append(f'<div class="seg {severity}" style="width:{width}%"'f' title="{severity}: {value}"></div>')
            severity_index = severity_index + 1
        segments_html = "".join(segments)
        parts.append(f'<div class="row"><div class="name">{esc(day)}</div>'f'<div class="track">{segments_html}</div>'f'<div class="count">{day_total}</div></div>')
        index = index + 1
    return "\n".join(parts)

def build_simple_chart(pairs):
    if len(pairs) == 0:
        return '<p class="empty">No data.</p>'
    max_value = 0
    index = 0
    while index < len(pairs):
        if pairs[index][1] > max_value:
            max_value = pairs[index][1]
        index = index + 1
    parts = []
    index = 0
    while index < len(pairs):
        name = pairs[index][0]
        value = pairs[index][1]
        width = percent_of(value, max_value)
        parts.append(f'<div class="row"><div class="name">{esc(name)}</div>'f'<div class="track"><div class="seg plain" style="width:{width}%">'f'</div></div><div class="count">{value}</div></div>')
        index = index + 1
    return "\n".join(parts)

def build_raw_alerts(alerts):
    if len(alerts) == 0:
        return '<p class="empty">No raw alerts.</p>'
    newest_first = sorted(alerts, key=inc.alert_time, reverse=True)
    parts = []
    parts.append(f'<details><summary>Show the latest {RAW_ALERTS_LIMIT} raw alerts 'f'(of {len(alerts)})</summary>')
    parts.append('<table><tr><th>Time</th><th>Source</th><th>Type</th></tr>')
    index = 0
    while index < len(newest_first) and index < RAW_ALERTS_LIMIT:
        alert = newest_first[index]
        time_text = inc.format_time(alert["time"])
        parts.append(f'<tr><td>{esc(time_text)}</td>'f'<td><code>{esc(alert["src"])}</code></td>'f'<td>{esc(alert["type"])}</td></tr>')
        index = index + 1
    parts.append('</table></details>')
    return "\n".join(parts)


def build_page(alerts, incident_list, source_path):
    generated = datetime.now().strftime(inc.TIME_FORMAT)
    type_counts = inc.count_by_type(incident_list)
    type_pairs = list(type_counts.items())
    type_pairs.sort(key=inc.pair_count, reverse=True)
    sources = inc.top_sources(incident_list, TOP_SOURCES_LIMIT)
    parts = []
    parts.append('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append('<title>Home IDS - Incidents</title>')
    parts.append('<style>' + CSS + '</style></head><body>')
    parts.append('<h1>Home <span>IDS</span> - Incidents</h1>')
    parts.append(f'<div class="subtitle">Source: <code>{esc(source_path)}</code> 'f'&middot; generated {esc(generated)}</div>')
    parts.append(build_cards(incident_list, len(alerts)))
    parts.append('<h2>Incidents (by priority)</h2>')
    parts.append('<div class="panel">' + build_incident_table(incident_list) + '</div>')
    parts.append('<h2>Incidents per day</h2>')
    parts.append('<div class="panel">' + build_day_chart(incident_list) + '</div>')
    parts.append('<h2>Incidents per type</h2>')
    parts.append('<div class="panel">' + build_simple_chart(type_pairs) + '</div>')
    parts.append('<h2>Top sources</h2>')
    parts.append('<div class="panel">' + build_simple_chart(sources) + '</div>')
    parts.append('<h2>Raw alerts</h2>')
    parts.append('<div class="panel">' + build_raw_alerts(alerts) + '</div>')
    parts.append('</body></html>')
    return "\n".join(parts)

def main():
    path = DEFAULT_ALERTS_PATH
    if len(sys.argv) > 1:
        path = sys.argv[1]
    alerts = inc.load_alerts(path)
    incident_list = inc.build_incidents(alerts)
    page = build_page(alerts, incident_list, path)
    file = open(OUTPUT_PATH, "w")
    file.write(page)
    file.close()
    print(f"{len(alerts)} alerts -> {len(incident_list)} incidents")
    print(f"Dashboard written to {OUTPUT_PATH}")

if __name__ == "__main__":
    main()