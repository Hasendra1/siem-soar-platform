# SIEM·SOAR — IoT/OT Security Platform

A production-grade **Security Information and Event Management (SIEM) + Security Orchestration, Automation and Response (SOAR)** platform built for IoT/OT network threat detection and automated response.

![Platform](https://img.shields.io/badge/Platform-IoT%2FOT%20Security-blue)
![Stack](https://img.shields.io/badge/Stack-React%20%2B%20Flask%20%2B%20SQLite-green)
![ML](https://img.shields.io/badge/ML-Ensemble%20Anomaly%20Detection-purple)

---

## 🔍 Overview

This platform monitors industrial IoT/OT networks in real time, detects cyber threats using machine learning, and automatically isolates compromised devices using Docker network segmentation.

### Key Capabilities

| Feature | Details |
|---------|---------|
| **Real-time monitoring** | WebSocket-driven live event feed from network sensors |
| **ML anomaly detection** | Ensemble model (Isolation Forest + Autoencoder + LSTM) |
| **Automated isolation** | Docker network segmentation + iptables rules |
| **Incident management** | Full lifecycle: OPEN → INVESTIGATING → CONTAINED → RESOLVED |
| **Threat hunting** | Advanced query builder across all network events |
| **MITRE ATT&CK mapping** | Detection rules mapped to ATT&CK techniques |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│           React Frontend (Vite)             │
│  Dashboard · Incidents · Threat Hunting     │
│  Isolated Devices · Anomalies · Rules       │
└──────────────┬──────────────────────────────┘
               │ REST API + WebSocket (SocketIO)
┌──────────────▼──────────────────────────────┐
│           Flask Backend (port 5000)         │
│  /api/dashboard  /api/data  /api/investigation│
└──────────────┬──────────────────────────────┘
               │
┌──────────────▼──────────────────────────────┐
│         SQLite Database                     │
│  events · anomalies · incidents · isolations│
│  devices · clusters · investigations        │
└─────────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────┐
│         ML Pipeline + Agents                │
│  live_attack_simulator · ml_segmentation    │
│  attacker_identification · db_manager       │
└─────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
siem-soar-platform/
├── api/                        # Flask REST API
│   ├── app.py                  # Main Flask app + SocketIO
│   ├── routes_dashboard.py     # Dashboard endpoints
│   ├── routes_data.py          # Events/anomalies + query
│   ├── routes_investigation.py # Incident CRUD lifecycle
│   └── websocket_server.py     # Real-time push
│
├── frontend-react/             # React + Vite + Tailwind
│   └── src/
│       ├── pages/
│       │   ├── Dashboard.jsx       # SOC overview
│       │   ├── IsolatedDevices.jsx # Device isolation view
│       │   ├── RulesTriggered.jsx  # Detection rules + MITRE
│       │   ├── AnomaliesDetected.jsx # ML anomaly analysis
│       │   ├── Incidents.jsx       # Incident management
│       │   └── ThreatHunting.jsx   # Advanced search
│       └── components/
│
├── agents/
│   └── live_attack_simulator.py    # Simulates realistic attacks
│
├── ml_models/
│   └── attacker_identification.py  # ML ensemble classifier
│
├── enforcement/
│   └── ml_based_segmentation.py    # Docker network isolation
│
├── database/
│   └── db_manager.py               # SQLite ORM layer
│
├── dataset/                        # CSV datasets + DB schema
├── run_full_pipeline.py            # One-click full system start
└── run_complete_system.bat         # Windows batch launcher
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+
- Docker Desktop (for isolation features)

### 1. Clone
```bash
git clone https://github.com/YOUR_USERNAME/siem-soar-platform.git
cd siem-soar-platform
```

### 2. Backend
```bash
pip install flask flask-cors flask-socketio sqlite3
cd api
python app.py
# API running at http://localhost:5000
```

### 3. Frontend
```bash
cd frontend-react
npm install
npm run dev
# UI running at http://localhost:5173
```

### 4. Attack Simulator (optional)
```bash
python agents/live_attack_simulator.py
```

---

## 🖥️ Pages

| Page | Route | Description |
|------|-------|-------------|
| Dashboard | `/dashboard` | SOC overview with threat gauge, topology, live events |
| Isolated Devices | `/isolated-devices` | Real-time isolation status + network zone badges |
| Rules Triggered | `/rules-triggered` | Detection rules with MITRE ATT&CK mapping |
| Anomalies Detected | `/anomalies-detected` | ML ensemble scoring and analysis |
| Incidents | `/incidents` | Full incident lifecycle management |
| Threat Hunting | `/threat-hunting` | Advanced multi-field query builder + export |
| Settings | `/settings` | Platform configuration |

---

## 🔌 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard/summary` | Overall threat status |
| GET | `/api/dashboard/isolations` | Active isolations |
| GET | `/api/dashboard/rules-triggered` | Fired detection rules |
| GET | `/api/dashboard/anomalies-detailed` | ML anomaly details |
| POST | `/api/data/events/query` | Advanced event search |
| GET | `/api/investigation/incidents` | List all incidents |
| POST | `/api/investigation/incidents` | Create incident |
| PUT | `/api/investigation/incidents/:id` | Update incident status |
| DELETE | `/api/investigation/incidents/:id` | Delete incident |

---

## 🛡️ Detection Capabilities

- **Port Scanning** — Rapid multi-port connection attempts
- **Unauthorized Modbus Read/Write** — ICS protocol abuse
- **Lateral Movement** — Cross-zone IP pivoting
- **Data Exfiltration** — High-volume outbound transfers
- **MQTT Injection** — IoT broker manipulation
- **Attacker Identification** — ML-based classification (98.5% confidence)

---

## 📊 Tech Stack

**Frontend:** React 18, Vite, Tailwind CSS, Recharts, Lucide Icons, Socket.IO Client  
**Backend:** Python 3.10, Flask, Flask-CORS, Flask-SocketIO  
**Database:** SQLite (via `sqlite3`)  
**ML:** scikit-learn, Isolation Forest, custom ensemble  
**DevOps:** Docker (network isolation), PowerShell scripts

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
