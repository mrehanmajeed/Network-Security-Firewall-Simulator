# Network Security Scanner & Firewall Visualizer
### Information Security Assignment 3

---

## Features
- **Port Scanner** — TCP Connect, TCP SYN, UDP, Version Detection via python-nmap
- **Socket Scan Fallback** — Works even if nmap is not installed
- **Firewall Rule Engine** — Add ALLOW/DENY rules with priority chaining
- **Traffic Simulation** — Simulate a packet and trace it through all firewall rules
- **Network Diagram** — Canvas-based traffic flow visualization
- **Summary Chart** — Open ports grouped by service

## Quick Start

### 1. Install nmap (system)
```bash
# Ubuntu/Debian
sudo apt install nmap

# macOS
brew install nmap

# Windows — download from https://nmap.org/download
```

### 2. Install Python dependencies
```bash
pip install flask python-nmap
```

### 3. Run
```bash
python A3_app.py
```
Open `http://127.0.0.1:5000` in your browser.

> **Note:** If nmap is not installed, click "⚡ Socket Scan" instead — it uses Python's built-in sockets.

## Usage
1. **Port Scanner tab** — Enter target IP/hostname, choose scan type and port range, click Scan
2. **Firewall Rules tab** — Add ALLOW/DENY rules; use Quick Rules for common policies
3. **Simulate Traffic tab** — Enter a source IP + port, click Run Simulation to trace through rules
4. **Network Diagram tab** — View the traffic flow canvas after running a simulation

## Tech Stack
- Backend: Python + Flask + python-nmap
- Frontend: HTML5, CSS3, JavaScript (no external frameworks)
- Canvas: Native HTML5 Canvas API for diagrams
