import psutil
import time
import json
import os
from datetime import datetime
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "..", "logs", "edr.log")

# -------------------------------
# HARDENING CONFIG
# -------------------------------
TIME_WINDOW = 30
THRESHOLD = 6
CHECK_INTERVAL = 2
ALERT_COOLDOWN = 60

TRUSTED_PROCESSES = [
    "chrome", "firefox", "chromium",
    "brave", "opera",
    "code", "codium"
]

connection_log = defaultdict(list)
last_alert_time = {}

print("[EDR] Network monitor (hardened) started")

def is_public_ip(ip):
    return not (
        ip.startswith("127.") or
        ip.startswith("10.") or
        ip.startswith("192.168.")
    )

while True:
    for conn in psutil.net_connections(kind="inet"):
        if not conn.raddr or not conn.pid:
            continue

        try:
            proc = psutil.Process(conn.pid)
            pname = proc.name().lower()
            user = proc.username()
        except:
            continue

        # 🔒 Ignore trusted applications
        if pname in TRUSTED_PROCESSES:
            continue

        remote_ip = conn.raddr.ip
        if not is_public_ip(remote_ip):
            continue

        key = (pname, remote_ip)
        now = time.time()
        connection_log[key].append(now)

        # Sliding window
        connection_log[key] = [
            t for t in connection_log[key]
            if now - t <= TIME_WINDOW
        ]

        # 🚨 Possible C2 beacon
        if len(connection_log[key]) >= THRESHOLD:

            alert_key = f"{pname}_{remote_ip}"
            if alert_key in last_alert_time and now - last_alert_time[alert_key] < ALERT_COOLDOWN:
                continue

            last_alert_time[alert_key] = now

            event = {
                "timestamp": str(datetime.now()),
                "type": "NETWORK",
                "severity": "HIGH",
                "reason": "Possible C2 beaconing (repeated outbound connections)",
                "process": pname,
                "remote_ip": remote_ip,
                "user": user
            }

            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(event) + "\n")

            print("[C2 ALERT]", event)

            connection_log[key] = []

    time.sleep(CHECK_INTERVAL)
