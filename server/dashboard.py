from flask import Flask, render_template_string
import json
import os

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "..", "logs", "edr.log")

HTML = """
<!doctype html>
<html>
<head>
    <title>Mini-EDR SOC Dashboard</title>
    <style>
        body { font-family: Arial; background: #111; color: #eee; }
        h1 { color: #ff4444; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #444; padding: 8px; }
        th { background: #222; }
        tr:hover { background: #333; }
    </style>
</head>
<body>
    <h1>🚨 Mini-EDR SOC Dashboard (Hardened)</h1>
    <table>
        <tr>
            <th>Time</th>
            <th>Type</th>
            <th>User</th>
            <th>Process / Path</th>
            <th>Reason</th>
        </tr>
        {% for e in events %}
        <tr>
            <td>{{ e.time }}</td>
            <td>{{ e.type }}</td>
            <td>{{ e.user }}</td>
            <td>{{ e.object }}</td>
            <td>{{ e.reason }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

@app.route("/")
def index():
    events = []

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            for line in f.readlines()[-200:]:
                try:
                    e = json.loads(line)
                except:
                    continue

                # 🔒 HARDENING: show only HIGH severity
                if e.get("severity") != "HIGH":
                    continue

                events.append({
                    "time": e.get("timestamp", ""),
                    "type": e.get("type", ""),
                    "user": e.get("user", "-"),
                    "object": e.get("process", e.get("path", "-")),
                    "reason": e.get("reason", "")
                })

    events.reverse()
    return render_template_string(HTML, events=events)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
