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

Project Structure

mini-edr/
├── agent/
│   ├── process_monitor.py      # Detects malicious process behavior
│   ├── file_monitor.py         # Detects ransomware-style file activity
│   ├── network_monitor.py      # Detects C2-like network beaconing
│
├── server/
│   ├── detector.py             # Central detection & correlation engine
│   ├── dashboard.py            # SOC-style Flask dashboard
│
├── monitored_dir/              # Directory used for ransomware testing
├── logs/
│   └── edr.log                 # Central JSON event log
│
├── start_edr.sh                # Service launcher script
├── README.md
├── .gitignore
└── venv/                       # Python virtual environment (NOT pushed to GitHub)
'''
