import psutil
import time
import json
import os
from datetime import datetime

# -------------------------------------------------
# Paths
# -------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "..", "logs", "edr.log")

print("[EDR] Process monitor started")

# -------------------------------------------------
# Helper: get parent process name
# -------------------------------------------------
def get_parent_name(ppid):
    try:
        return psutil.Process(ppid).name().lower()
    except:
        return "unknown"

# -------------------------------------------------
# Main monitoring loop
# -------------------------------------------------
while True:
    for proc in psutil.process_iter(
        ['pid', 'ppid', 'name', 'cmdline', 'username']
    ):
        try:
            pname = (proc.info['name'] or "").lower()
            cmd = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
            user = proc.info['username']
            ppid = proc.info['ppid']
            parent_name = get_parent_name(ppid)

            # -------------------------------------------------
            # 1️⃣ Ignore system / root processes
            # -------------------------------------------------
            if user in ["root", None]:
                continue

            severity = None
            reason = None

            # -------------------------------------------------
            # 2️⃣ RULE-1: Script downloading from internet
            # bash / sh / python + curl / wget / http
            # -------------------------------------------------
            if (
                pname in ["bash", "sh", "python"] and
                ("curl" in cmd or "wget" in cmd or "http" in cmd)
            ):
                severity = "HIGH"
                reason = "Script downloading from internet"

            # -------------------------------------------------
            # 3️⃣ RULE-2: Direct wget / curl execution
            # -------------------------------------------------
            elif pname in ["wget", "curl"] and "http" in cmd:
                severity = "HIGH"
                reason = "Direct download via command-line tool"

            # -------------------------------------------------
            # 4️⃣ RULE-3: Suspicious parent → child chain
            # Example: bash → wget, python → curl, bash → sh
            # -------------------------------------------------
            elif (
                parent_name in ["bash", "sh", "python"] and
                pname in ["wget", "curl", "sh"]
            ):
                severity = "HIGH"
                reason = f"Suspicious process chain: {parent_name} → {pname}"

            # -------------------------------------------------
            # 5️⃣ No rule matched → ignore
            # -------------------------------------------------
            else:
                continue

            # -------------------------------------------------
            # 6️⃣ Create alert event
            # -------------------------------------------------
            event = {
                "timestamp": str(datetime.now()),
                "type": "PROCESS",
                "severity": severity,
                "reason": reason,
                "process": pname,
                "parent": parent_name,
                "cmd": cmd,
                "user": user
            }

            # -------------------------------------------------
            # 7️⃣ Log ONLY real alerts
            # -------------------------------------------------
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(event) + "\n")

            print("[PROCESS ALERT]", event)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Fast scan for short-lived processes
    time.sleep(0.2)
