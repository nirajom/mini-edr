from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import json
import os
from datetime import datetime

# -------------------------------------------------
# Paths
# -------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MONITOR_DIR = os.path.join(BASE_DIR, "..", "monitored_dir")
LOG_FILE = os.path.join(BASE_DIR, "..", "logs", "edr.log")

# -------------------------------------------------
# Ransomware detection config
# -------------------------------------------------
TIME_WINDOW = 5            # seconds window
THRESHOLD = 10             # file modifications
RANSOMWARE_COOLDOWN = 60   # seconds (ONLY ONE alert per attack)

event_times = []
last_ransomware_alert = 0  # timestamp of last ransomware alert

print("[EDR] File monitor (ransomware detection) started")

# -------------------------------------------------
# File event handler
# -------------------------------------------------
class Handler(FileSystemEventHandler):

    def on_modified(self, event):
        global event_times
        global last_ransomware_alert

        if event.is_directory:
            return

        now = time.time()
        event_times.append(now)

        # 🔹 Remove old events outside time window
        event_times = [t for t in event_times if now - t <= TIME_WINDOW]

        # -------------------------------------------------
        # 🚨 RANSOMWARE DETECTION (ONCE-ONLY)
        # -------------------------------------------------
        if len(event_times) >= THRESHOLD:

            # ⏳ Cooldown: already alerted recently
            if now - last_ransomware_alert < RANSOMWARE_COOLDOWN:
                return

            last_ransomware_alert = now

            alert = {
                "timestamp": str(datetime.now()),
                "type": "FILE",
                "severity": "HIGH",
                "reason": "Possible ransomware behavior (mass file modification)",
                "path": event.src_path
            }

            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(alert) + "\n")

            print("[RANSOMWARE ALERT]", alert)

            # reset counters after incident
            event_times = []
            return

        # -------------------------------------------------
        # INFO-level file modification (noise)
        # -------------------------------------------------
        info = {
            "timestamp": str(datetime.now()),
            "type": "FILE",
            "severity": "INFO",
            "action": "MODIFIED",
            "path": event.src_path
        }

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(info) + "\n")

# -------------------------------------------------
# Observer setup
# -------------------------------------------------
observer = Observer()
observer.schedule(Handler(), MONITOR_DIR, recursive=True)
observer.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()

observer.join()
