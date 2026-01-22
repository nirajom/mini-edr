import json
import time
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "..", "logs", "edr.log")

# -------------------------------
# HARDENING CONFIG
# -------------------------------
ALERT_COOLDOWN = 30        # seconds (for duplicate alerts)
RANSOMWARE_COOLDOWN = 60   # seconds (single incident)

last_alert_time = {}

print("[DETECTOR] Started")

while True:
    if not os.path.exists(LOG_FILE):
        time.sleep(2)
        continue

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    for line in lines:
        try:
            event = json.loads(line)
        except:
            continue

        # 🔒 HARDENING: only HIGH severity
        if event.get("severity") != "HIGH":
            continue

        event_type = event.get("type", "UNKNOWN")
        reason = event.get("reason", "Suspicious activity")
        now = time.time()

        # ===============================
        # PROCESS ALERT HANDLING
        # ===============================
        if event_type == "PROCESS":
            user = event.get("user", "unknown")
            process = event.get("process", "unknown")
            parent = event.get("parent", "unknown")

            key = f"PROC_{process}_{reason}"

            # ⏳ Cooldown to avoid spam
            if key in last_alert_time and now - last_alert_time[key] < ALERT_COOLDOWN:
                continue

            last_alert_time[key] = now

            print(
                f"🚨 ALERT | PROCESS | "
                f"user={user} | process={process} | parent={parent} | "
                f"reason={reason}"
            )

        # ===============================
        # FILE / RANSOMWARE ALERT
        # ===============================
        elif event_type == "FILE":
            key = "RANSOMWARE_INCIDENT"

            # ⏳ Single incident logic
            if key in last_alert_time and now - last_alert_time[key] < RANSOMWARE_COOLDOWN:
                continue

            last_alert_time[key] = now

            path = event.get("path", "multiple files")

            print(
                f"🚨 ALERT | FILE | "
                f"reason={reason} | path={path}"
            )

    time.sleep(2)
