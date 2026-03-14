# AI-Powered IDPS

An AI-powered Intrusion Detection and Prevention System (IDPS) that combines Suricata IDS alerts, packet capture analysis, anomaly detection, automated IP blocking, and a React-based monitoring dashboard.

This project is built as a full-stack security monitoring platform with:

- A React frontend for dashboards, alerts, reports, blocked IP management, system health, and geolocation-based risk analysis
- A FastAPI backend for threat ingestion, analytics, automation, and control APIs
- An AI detection pipeline that merges Suricata logs and PCAP-derived traffic, scores anomalies, and writes suspicious IPs to a blocklist
- Shell automation for Linux firewall enforcement using `ipset` and `iptables`

## What The Project Does

The system is designed to help security teams monitor network events, identify suspicious behaviour, and take action quickly.

Core capabilities include:

- Real-time dashboard for live threats, blocked IPs, and alert counts
- Suricata IDS monitoring and control
- AI-assisted anomaly detection using `IsolationForest`
- Automatic and manual IP blocking workflows
- Risk scoring and geographic visualization of suspicious IPs
- Threat trend analysis and report generation
- System health monitoring for the backend host
- Traffic simulation for demo and testing scenarios

## High-Level Architecture

The repository has two main application layers:

### Frontend

Located in `frontend/`

- React 18 application
- Routing via `react-router-dom`
- Styling with Tailwind CSS and custom inline styles
- Visualizations with `react-leaflet`
- HTTP requests with `axios` and `fetch`

Main frontend pages:

- `Dashboard`: overview of alerts, live threats, blocked IPs, and IP search
- `Alerts`: tabular view of network events
- `Suricata IDS`: Suricata status, controls, alert statistics, and filtered recent alerts
- `Risk Map`: real-time geolocation-based risk map with IP analysis
- `Blocked IPs`: paginated blocklist management with manual block/unblock
- `Health`: CPU, memory, alert rate, model accuracy, connections, uptime
- `Reports`: daily/weekly/monthly reports and trend summaries

### Backend

Located in `ip-blocker/`

- FastAPI service exposed from `server.py`
- Uvicorn entry point in `main.py`
- Background monitor thread that periodically:
  - checks Suricata status
  - refreshes alert counters
  - runs the AI detection script
  - updates block-related state

Main backend responsibilities:

- Read Suricata alerts from `eve.json`
- Read merged traffic logs from CSV
- Expose REST APIs for dashboard, reports, risk analytics, and health
- Start, stop, and update Suricata
- Block and unblock IPs
- Simulate suspicious traffic using Scapy

### AI Detection Pipeline

The AI workflow lives in `ip-blocker/scripts/ai_detect.py`.

It:

1. Reads Suricata logs from `eve.json`
2. Reads new `.pcap` files with PyShark
3. Merges both sources into a single dataset
4. Enriches source IPs with GeoIP country information
5. Encodes protocol values for modeling
6. Runs `IsolationForest` anomaly detection
7. Writes suspicious IPs to `ip-blocker/datasets/ai_block.txt`
8. Saves merged data to `ip-blocker/datasets/merged_logs.csv`

The backend then triggers `dynamic_block.sh`, which applies the generated blocklist to Linux firewall controls through `ipset` and `iptables`.

## Tech Stack

### Main Technologies

- `⚛️ React` for the frontend dashboard
- `🎨 Tailwind CSS` for UI styling
- `🐍 Python` for backend and detection workflows
- `⚡ FastAPI` for REST APIs
- `🛡️ Suricata` for IDS monitoring
- `🧠 Scikit-learn` for anomaly detection
- `🗺️ Leaflet` for geolocation risk visualization
- `🔥 iptables` and `ipset` for IP blocking

## Repository Structure

```text
IDPS/
|-- frontend/
|   |-- public/
|   |-- src/
|   |   |-- components/
|   |   |-- services/
|   |   |-- utils/
|   |   |-- App.jsx
|   |   |-- index.js
|   |   `-- index.css
|   `-- package.json
|-- ip-blocker/
|   |-- datasets/
|   |-- scripts/
|   |-- main.py
|   `-- server.py
|-- screenshots/
`-- README.md
```

## Important Implementation Notes

- The frontend currently uses hardcoded backend URLs pointing to `http://34.222.107.115:8000/api`
- The backend CORS configuration is also set up for specific origins, including that host
- Several backend paths are hardcoded for a Linux or Ubuntu deployment
- Firewall automation scripts rely on Linux tools such as `ipset`, `iptables`, and `sudo`
- This means the full prevention workflow is primarily designed for a Linux server environment, even if the repository is viewed or edited on Windows

## Key API Endpoints

The FastAPI backend exposes endpoints such as:

- `GET /api/dashboard_stats`
- `GET /api/live_threats`
- `GET /api/ip/search/{ip}`
- `GET /api/system_health`
- `GET /api/blocked_ips`
- `POST /api/block_ip`
- `POST /api/unblock_ip`
- `GET /api/suricata/alerts`
- `GET /api/suricata/statistics`
- `GET /api/vps/status`
- `POST /api/suricata/start`
- `POST /api/suricata/stop`
- `POST /api/suricata/rules/update`
- `GET /api/risk/top_risks`
- `GET /api/risk/statistics`
- `GET /api/risk/analyze/{ip}`
- `POST /api/risk/simulate/{ip}`
- `GET /api/threat_trends`
- `GET /api/generate_report?type=daily|weekly|monthly`

## How The System Flows

1. Suricata generates alerts in `eve.json`
2. PCAP files are optionally ingested for additional traffic visibility
3. The AI script merges traffic sources and detects anomalous IPs
4. Suspicious IPs are written to `ai_block.txt`
5. Blocking scripts apply those IPs to firewall controls
6. The FastAPI backend exposes data and controls through REST APIs
7. The React frontend polls the backend and renders dashboards, tables, reports, and risk maps

## Setup

### Frontend Setup

From `frontend/`:

```bash
npm install
npm start
```

Production build:

```bash
npm run build
```

The frontend runs on port `3000` by default.

### Backend Setup

There is no Python dependency file in the repository, so dependencies must be installed manually.

Typical packages required by the current codebase include:

```bash
pip install fastapi uvicorn pydantic psutil python-dateutil pytz scapy pandas geoip2 pyshark scikit-learn
```

From `ip-blocker/`:

```bash
python main.py
```

This starts the FastAPI app with Uvicorn on port `8000`.

## Suricata And Linux Requirements

For full IDS and prevention functionality, the target server should provide:

- Suricata installed and accessible
- `eve.json` logging enabled
- Linux support for `ipset` and `iptables`
- Sudo privileges for firewall updates
- GeoIP database file for `geoip2`
- A packet capture directory if PCAP ingestion is used

## Demo / Simulation Support

The project includes built-in simulation behavior for demos:

- The risk map can trigger sample traffic simulation for known mock IPs
- The backend contains mock geolocation data for select IP addresses
- If Scapy packet sending fails, the backend can fall back to writing mock alerts into `eve.json`
- The Suricata page exposes status information and can operate in a simulation-style mode when Suricata is not fully available

## Main Screens And Features

### 📊 Dashboard

- Summary counters for alerts and blocked IPs
- Live threat feed
- Blocked IP preview
- IP log search

### 🚨 Alerts

- Threat table with pagination
- Source and destination visibility
- Protocol, threat type, and anomaly status display

### 🛡️ Suricata IDS

- Running or stopped status
- Install or simulation visibility
- Start, stop, and update rules controls
- Alert statistics by category and signature
- Filtered recent alert stream

### 🌍 Risk Map

- World map with geolocated risky IPs
- Risk score and threat level calculation
- Drill-down IP analysis
- Search, sort, pagination, and auto refresh
- Simulated threat generation for demo testing

### ⛔ Blocked IPs

- Manual IP block input
- Paginated blocklist view
- Unblock workflow

### ❤️ Health

- CPU and memory monitoring
- Alerts per minute
- Model accuracy indicator
- Active connections and uptime

### 📑 Reports

- Daily, weekly, and monthly report generation
- Top threats and severity summary
- Geographic distribution and threat trend views
- Plain-text report export

## Current Strengths

- Clear full-stack separation between UI and detection backend
- Practical analyst dashboard coverage
- Real prevention workflow through blocklist automation
- Good demo value through simulation and map-based analytics
- Multiple operational views: alerts, risk, health, reports, and block management

## 🖼️ Screenshots

### Dashboard Page.jpeg

<img src="screenshots/Dashboard%20Page.jpeg" alt="Dashboard Page.jpeg" title="Dashboard Page.jpeg" />

### Dashboard Page (IP log search bar).jpeg

<img src="screenshots/Dashboard%20Page%20%28IP%20log%20search%20bar%29.jpeg" alt="Dashboard Page (IP log search bar).jpeg" title="Dashboard Page (IP log search bar).jpeg" />

### Alerts Page.jpeg

<img src="screenshots/Alerts%20Page.jpeg" alt="Alerts Page.jpeg" title="Alerts Page.jpeg" />

### Blocked IPs Page.jpeg

<img src="screenshots/Blocked%20IPs%20Page.jpeg" alt="Blocked IPs Page.jpeg" title="Blocked IPs Page.jpeg" />

### Health Page.jpeg

<img src="screenshots/Health%20Page.jpeg" alt="Health Page.jpeg" title="Health Page.jpeg" />

### Reports Page.jpeg

<img src="screenshots/Reports%20Page.jpeg" alt="Reports Page.jpeg" title="Reports Page.jpeg" />

### Reports Page (Monthly report & threat type).jpeg

<img src="screenshots/Reports%20Page%20%28Monthly%20report%20%26%20threat%20type%29.jpeg" alt="Reports Page (Monthly report & threat type).jpeg" title="Reports Page (Monthly report & threat type).jpeg" />

### Risk Map Page.jpeg

<img src="screenshots/Risk%20Map%20Page.jpeg" alt="Risk Map Page.jpeg" title="Risk Map Page.jpeg" />

### Suricata IDS Page.jpeg

<img src="screenshots/Suricata%20IDS%20Page.jpeg" alt="Suricata IDS Page.jpeg" title="Suricata IDS Page.jpeg" />

### Suricata IDS Page (Category Filter).jpeg

<img src="screenshots/Suricata%20IDS%20Page%20%28Category%20Filter%29.jpeg" alt="Suricata IDS Page (Category Filter).jpeg" title="Suricata IDS Page (Category Filter).jpeg" />
