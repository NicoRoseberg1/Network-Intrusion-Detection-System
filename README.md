# 🛡️ AegisNIDS — Cyber Security Operations Center (SOC) & Automated IPS

An enterprise-grade, full-stack Cyber Security Operations Center (SOC) web application featuring real-time Deep Packet Inspection (DPI), autonomous Intrusion Prevention System (IPS) IP blocking, custom Snort-style rule policies, and an interactive REST API built with **FastAPI, WebSockets, Chart.js, and Tailwind CSS**.

![Web SOC](https://img.shields.io/badge/Interface-FastAPI%20Cyber%20SOC-0284c7?style=flat-square)
![REST API](https://img.shields.io/badge/API-Swagger%20OpenAPI%203.0-16a34a?style=flat-square)
![Detection Engine](https://img.shields.io/badge/RFC%20793-Compliant-emerald?style=flat-square)
![Active IPS](https://img.shields.io/badge/Firewall-Autonomous%20Drops-rose?style=flat-square)

---

## 🌟 Key Capabilities & Enterprise Features

### 1. Modern Dark-Mode Cyber SOC Web Application
- **Live Throughput Velocity:** Real-time animated line charts tracking packet stream velocity.
- **Protocol & Threat Analytics:** Donut charts for TCP/UDP/ICMP and severity distribution bars.
- **Real-Time Streaming Packet Ticker:** Live Layer-3 and Layer-4 packet inspector.
- **Autonomous Host Discovery:** Discovers subnet nodes and calculates dynamic **Risk Scores (0–100)**.

### 2. Active Intrusion Prevention System (IPS) Firewall
- **1-Click IP Banning:** Instantly block rogue attacker IPs directly from the alert feed.
- **Autonomous Packet Drops:** Packets from banned IPs are actively dropped by the firewall engine.
- **Live Drop Counters:** Tracks the exact number of malicious packets blocked per IP in real time.

### 3. Custom Snort-Style Detection Rule Policy Engine
- Security analysts can create and deploy custom rules via the web UI (Protocol, Target Port, Packet Count Threshold, Action: `ALERT` or `DROP`, Severity).
- Toggle rules ON/OFF with live switches.

### 4. Multi-Vector RFC 793 Threat Heuristics
- **Stealth Scans:** Detects RFC 793 violations including **NULL Scans** (zero flags set), **XMAS Scans** (FIN+PSH+URG), and **FIN Scans**.
- **TCP SYN Flood (DoS):** Identifies half-open connection floods exhausting kernel socket buffers.
- **Port Scanning:** Detects horizontal and vertical port reconnaissance cardinality.
- **ICMP Echo Ping Flood:** Flags volumetric ICMP bandwidth saturation.
- **Privileged Port Probing:** Monitors sensitive ports (SSH: 22, Telnet: 23, SMB: 445, RDP: 3389, MySQL: 3306).

### 5. Interactive Swagger / OpenAPI REST API (`/docs`)
- Full RESTful microservice architecture allowing external SIEM tools to query stats, alerts, blocklist, and custom rules.

---

## 🚀 Running the Application

### 1. Activate Environment & Start Server
```bash
cd Network_Intrusion_Detector_Mini_Project

# Windows PowerShell:
.\.venv\Scripts\activate

# Run the Cyber SOC Web Application:
python -m uvicorn server:app --host 0.0.0.0 --port 8000 --reload
```

- **Live SOC Web Dashboard:** 👉 **[http://localhost:8000](http://localhost:8000)**
- **Interactive REST API Documentation (Swagger):** 👉 **[http://localhost:8000/docs](http://localhost:8000/docs)**

---

## 📂 Project Structure

```
├── server.py            # FastAPI production backend & RESTful microservice
├── templates/
│   └── index.html       # Single Page Application (Tailwind CSS, Chart.js, Cyber UI)
├── detector.py          # Threat engine, blocklist enforcement, and scenario simulator
├── storage.py           # SQLite database layer (alerts, blocklist, custom rules, assets)
├── capture.py           # Scapy live packet dissection and interface discovery
├── app.py               # Optional Streamlit dashboard
├── report_outline.md    # Detailed academic evaluation report & viva notes
├── requirements.txt     # Python dependencies
└── data/
    └── alerts.db        # Persistent SQLite incident database
```


