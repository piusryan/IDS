Here is a **short, clean README text version** (you can paste directly into GitHub):

---

**README.txt (Short Version)**

```
Python Intrusion Detection System (IDS)
---------------------------------------

A simple Python-based IDS that uses Scapy to sniff packets and Flask to display
a real-time dashboard. It detects suspicious traffic patterns using both
rate-based and signature-based rules.

Features:
- Live packet capture (source, destination, protocol)
- Suspicious traffic alerts (UDP flood, ICMP flood, malicious IPs, etc.)
- Web dashboard with auto-refresh
- Lightweight and easy to run

How to Run:
1. Install dependencies:
   pip install -r requirements.txt

2. Start IDS (admin privileges may be required):
   sudo python app.py

3. Open dashboard:
   http://localhost:5000/

API Endpoints:
- /packets → recent packet list
- /alerts → active alerts

Files:
- app.py         → Flask server + API
- sniffer.py     → Packet sniffer + detection
- sniffer.txt    → Signature rules
- templates/     → HTML dashboard
- static/        → JS + CSS files

Notes:
- Use only on networks you own or have permission to monitor.
- Educational project for cybersecurity practice.

```

---

If you want an **even shorter** version (5–6 lines), tell me **"shorter"**.
