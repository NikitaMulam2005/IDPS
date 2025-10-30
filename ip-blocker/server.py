from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from threading import Thread
from pydantic import BaseModel
from collections import Counter
from typing import List, Optional, Dict, Tuple
from datetime import datetime, timedelta
from dateutil.parser import parse as parse_datetime
import pytz
import json
import os
from pathlib import Path
import psutil
import subprocess
import time
from scapy.all import IP, TCP, UDP, send, RandShort
import random
import csv


app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://34.222.107.115:3000",
        "http://127.0.0.1:3000",
        "http://34.222.107.115",
        "http://34.222.107.115:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Debug middleware
@app.middleware("http")
async def log_requests(request, call_next):
    print(f"Incoming request: {request.method} {request.url} from {request.headers.get('origin')}")
    response = await call_next(request)
    print(f"Response headers: {response.headers}")
    return response

# Custom exception handler
@app.exception_handler(Exception)
async def custom_exception_handler(request, exc):
    headers = {
        "Access-Control-Allow-Origin": request.headers.get("origin", "http://localhost:3000"),
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS, DELETE, PUT",
        "Access-Control-Allow-Headers": "*",
        "Vary": "Origin",
    }
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal server error: {str(exc)}"},
        headers=headers,
    )

# Paths & Global Status
SURICATA_PATH = "/usr/bin/suricata"
EVE_JSON_PATH = "/var/log/suricata/eve.json"  # Updated to match ai_detect.py
MERGED_LOGS_CSV = "/home/ubuntu/idps/ip-blocker/datasets/merged_logs.csv"
IP_BLOCK_TXT = "/home/ubuntu/idps/ip-blocker/datasets/ai_block.txt"
DYNAMIC_BLOCK_SCRIPT = "/home/ubuntu/idps/ip-blocker/scripts/dynamic_block.sh"
DYNAMIC_UNBLOCK_SCRIPT = "/home/ubuntu/idps/ip-blocker/scripts/dynamic_unblock.sh"
AI_DETECT_SCRIPT = "/home/ubuntu/idps/ip-blocker/scripts/ai_detect.py"

STATUS = {
    "running": False,
    "alerts_in_buffer": 0,
    "blocked_ips": 0
}

# Mock Geolocation Data
MOCK_GEO_DATA = {
    "114.114.114.114": {"latitude": 39.9042, "longitude": 116.4074, "country": "China", "city": "Beijing"},
    "192.168.1.100": {"latitude": 37.7749, "longitude": -122.4194, "country": "United States", "city": "San Francisco"},
    "8.8.8.8": {"latitude": 37.7510, "longitude": -97.8220, "country": "United States", "city": "Mountain View"},
    "198.51.100.22": {"latitude": 51.5074, "longitude": -0.1278, "country": "United Kingdom", "city": "London"},
    "203.0.113.10": {"latitude": 35.6762, "longitude": 139.6503, "country": "Japan", "city": "Tokyo"},
}

# Pydantic Models
class CountryCount(BaseModel):
    name: str
    count: int

class AlertType(BaseModel):
    name: str
    count: int

class LogEntry(BaseModel):
    src_ip: str
    dest_ip: str
    dest_port: Optional[int]
    proto: str
    attack_type: str
    timestamp: str
    country: Optional[str]
    proto_code: Optional[int]
    anomaly: Optional[float]

class AlertEntry(BaseModel):
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    proto: Optional[str] = None
    attack_type: Optional[str] = None
    timestamp: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[int] = None
    signature_id: Optional[int] = None
    anomaly: Optional[float] = None
    country: Optional[str] = None


class RiskEntry(BaseModel):
    ip: str
    latitude: float
    longitude: float
    country: str
    risk_score: float
    threat_level: str
    last_seen: str
    category: Optional[str]
    alert_count: int

class IPDetails(BaseModel):
    ip: str
    city: str
    country: str
    connection_count: int
    risk_score: float
    threat_level: str
    risk_factors: List[Dict]
    suspicious_activities: List[str]

class Statistics(BaseModel):
    total_ips: int
    average_risk_score: float
    threat_levels: Dict[str, int]

class BlockIPRequest(BaseModel):
    ip: str

class UnblockIPRequest(BaseModel):
    ip: str

class SystemHealth(BaseModel):
    cpu_usage: float
    memory_usage: float
    alerts_per_minute: float
    ml_model_accuracy: float
    active_connections: int
    uptime: float

class ThreatTrend(BaseModel):
    alert_types: List[AlertType]
    countries: List[CountryCount]
    reports: List[AlertEntry]

class ReportData(BaseModel):
    report_type: str
    generated_at: str
    total_alerts: int
    high_severity: int
    blocked_ips: int
    top_threats: List[Tuple[str, int]]

# Utility Functions
def is_suricata_running() -> bool:
    for proc in psutil.process_iter(['name', 'cmdline']):
        try:
            if proc.info['cmdline'] and 'suricata' in ' '.join(proc.info['cmdline']):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False

def read_merged_logs() -> List[LogEntry]:
    logs = []
    if not os.path.exists(MERGED_LOGS_CSV):
        print(f"Warning: {MERGED_LOGS_CSV} does not exist")
        return logs
    with open(MERGED_LOGS_CSV, newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            logs.append(
                LogEntry(
                    src_ip=row.get("src_ip", ""),
                    dest_ip=row.get("dest_ip", ""),
                    dest_port=int(row.get("dest_port", 0)) if row.get("dest_port") else None,
                    proto=row.get("proto", ""),
                    attack_type=row.get("attack_type", ""),
                    timestamp=row.get("timestamp", ""),
                    country=row.get("country"),
                    proto_code=int(row.get("proto_code", 0)) if row.get("proto_code") else None,
                    anomaly=float(row.get("anomaly", 0)) if row.get("anomaly") else None,
                )
            )
    return logs

def read_blocked_ips() -> List[str]:
    if not os.path.exists(IP_BLOCK_TXT):
        print(f"Warning: {IP_BLOCK_TXT} does not exist")
        return []
    try:
        with open(IP_BLOCK_TXT, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading {IP_BLOCK_TXT}: {e}")
        return []

def write_blocked_ips(blocked_ips: List[str]):
    try:
        os.makedirs(os.path.dirname(IP_BLOCK_TXT), exist_ok=True)
        with open(IP_BLOCK_TXT, "w") as f:
            f.write("\n".join(blocked_ips) + "\n")
    except Exception as e:
        print(f"Error writing to {IP_BLOCK_TXT}: {e}")
        raise HTTPException(status_code=500, detail=f"Error writing blocked IPs: {str(e)}")

def is_valid_ip(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                return False
        return True
    except:
        return False

def run_block_script():
    try:
        result = subprocess.run([DYNAMIC_BLOCK_SCRIPT], check=True, capture_output=True, text=True)
        print(f"dynamic_block.sh executed successfully: {result.stdout}")
        return {"status": "success", "message": result.stdout}
    except subprocess.CalledProcessError as e:
        print(f"Error running dynamic_block.sh: {e.stderr}")
        raise HTTPException(status_code=500, detail=f"Error running block script: {e.stderr}")

def run_unblock_script(ip: str):
    try:
        result = subprocess.run([DYNAMIC_UNBLOCK_SCRIPT, ip], check=True, capture_output=True, text=True)
        print(f"dynamic_unblock.sh executed successfully for {ip}: {result.stdout}")
        return {"status": "success", "message": result.stdout}
    except subprocess.CalledProcessError as e:
        print(f"Error running dynamic_unblock.sh for {ip}: {e.stderr}")
        raise HTTPException(status_code=500, detail=f"Error running unblock script: {e.stderr}")

def run_ai_detect_script():
    try:
        result = subprocess.run(["python3", AI_DETECT_SCRIPT], check=True, capture_output=True, text=True)
        print(f"ai_detect.py executed successfully: {result.stdout}")
        run_block_script()
        return {"status": "success", "message": result.stdout}
    except subprocess.CalledProcessError as e:
        print(f"Error running ai_detect.py: {e.stderr}")
        raise HTTPException(status_code=500, detail=f"Error running AI detection script: {e.stderr}")

def read_suricata_alerts(limit: Optional[int] = None) -> List[AlertEntry]:
    alerts: List[AlertEntry] = []
    if not os.path.exists(EVE_JSON_PATH):
        print(f"Error: {EVE_JSON_PATH} does not exist")
        return alerts
    try:
        with open(EVE_JSON_PATH) as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    if data.get("event_type") != "alert":
                        continue
                    alert_info = data.get("alert", {})
                    src_ip = data.get("src_ip", "")
                    geo = MOCK_GEO_DATA.get(src_ip, {"country": "Unknown"})
                    alerts.append(AlertEntry(
                        src_ip=src_ip,
                        src_port=data.get("src_port"),
                        dest_ip=data.get("dest_ip", ""),
                        dest_port=data.get("dest_port"),
                        proto=data.get("proto", ""),
                        attack_type=alert_info.get("signature", "Unknown"),
                        timestamp=data.get("timestamp", ""),
                        category=alert_info.get("category"),
                        severity=alert_info.get("severity"),
                        signature_id=alert_info.get("signature_id"),
                        country=geo["country"],
                        anomaly=None
                    ))
                except json.JSONDecodeError as e:
                    print(f"JSON decode error in {EVE_JSON_PATH}: {e}")
                    continue
        alerts.reverse()
        print(f"Read {len(alerts)} alerts from {EVE_JSON_PATH}")
        return alerts[:limit] if limit else alerts
    except Exception as e:
        print(f"Error reading {EVE_JSON_PATH}: {e}")
        return alerts

def calculate_alerts_per_minute() -> float:
    alerts = read_suricata_alerts()
    if not alerts:
        return 0.0
    now = datetime.now(pytz.UTC)
    five_minutes_ago = now - timedelta(minutes=5)
    alert_count = sum(1 for alert in alerts if parse_datetime(alert.timestamp) >= five_minutes_ago)
    alerts_per_minute = alert_count / 5.0 if alert_count > 0 else 0.0
    return round(alerts_per_minute, 2)

def filter_logs_by_time(logs: List[AlertEntry], time_range: str) -> List[AlertEntry]:
    now = datetime.now(pytz.UTC)
    if time_range == "daily":
        start_time = now - timedelta(days=1)
    elif time_range == "weekly":
        start_time = now - timedelta(days=7)
    elif time_range == "monthly":
        start_time = now - timedelta(days=30)
    else:
        raise HTTPException(
            status_code=400,
            detail="Invalid report type",
            headers={
                "Access-Control-Allow-Origin": "http://localhost:3000",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "*",
                "Vary": "Origin",
            },
        )

    filtered_logs = []
    for log in logs:
        try:
            log_time = parse_datetime(log.timestamp)
            if log_time.tzinfo is None:
                log_time = log_time.replace(tzinfo=pytz.UTC)
            if log_time >= start_time:
                filtered_logs.append(log)
        except ValueError as e:
            print(f"Error parsing timestamp {log.timestamp}: {e}")
            continue
    print(f"Filtered {len(filtered_logs)} logs for time range: {time_range}")
    return filtered_logs

def get_system_health() -> SystemHealth:
    cpu_usage = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    memory_usage = memory.percent
    alerts_per_minute = calculate_alerts_per_minute()
    ml_model_accuracy = 0.95
    active_connections = len(psutil.net_connections())
    uptime = time.time() - psutil.boot_time()
    return SystemHealth(
        cpu_usage=cpu_usage,
        memory_usage=memory_usage,
        alerts_per_minute=alerts_per_minute,
        ml_model_accuracy=ml_model_accuracy,
        active_connections=active_connections,
        uptime=uptime
    )

def calculate_risk_score(alerts: List[AlertEntry], ip: str) -> float:
    ip_alerts = [a for a in alerts if a.src_ip == ip or a.dest_ip == ip]
    if not ip_alerts:
        return 0.0
    severity_scores = {1: 0.9, 2: 0.7, 3: 0.4, 4: 0.2}
    total_score = sum(severity_scores.get(alert.severity, 0.1) for alert in ip_alerts)
    risk_score = min(total_score / max(len(ip_alerts), 1), 1.0)
    return round(risk_score, 3)

def get_threat_level(risk_score: float) -> str:
    if risk_score >= 0.8:
        return "CRITICAL"
    elif risk_score >= 0.6:
        return "HIGH"
    elif risk_score >= 0.4:
        return "MEDIUM"
    elif risk_score >= 0.2:
        return "LOW"
    else:
        return "MINIMAL"

def get_geo_data(ip: str) -> Dict:
    return MOCK_GEO_DATA.get(ip, {
        "latitude": random.uniform(-90, 90),
        "longitude": random.uniform(-180, 180),
        "country": "Unknown",
        "city": "Unknown"
    })

def simulate_suspicious_packet(ip: str, dest_ip: str = "192.168.1.100") -> Dict:
    try:
        attack_profiles = {
            "114.114.114.114": {
                "type": "ssh_scan",
                "port": 22,
                "proto": "TCP",
                "flags": "S",
                "category": "Potentially Bad Traffic",
                "severity": 1,
                "signature": "ET SCAN Potential SSH Scan",
                "signature_id": 2024143
            },
            "8.8.8.8": {
                "type": "http_suspicious",
                "port": 80,
                "proto": "TCP",
                "flags": "S",
                "category": "Policy Violation",
                "severity": 2,
                "signature": "ET POLICY Suspicious HTTP Method",
                "signature_id": 2024144
            },
            "192.168.1.100": {
                "type": "botnet_activity",
                "port": 6667,
                "proto": "TCP",
                "flags": "S",
                "category": "Malware",
                "severity": 2,
                "signature": "ET MALWARE Possible Botnet Activity",
                "signature_id": 2024145
            }
        }

        attack = attack_profiles.get(ip, {
            "type": "generic_scan",
            "port": 23,
            "proto": "TCP",
            "flags": "S",
            "category": "Potentially Bad Traffic",
            "severity": 3,
            "signature": "ET SCAN Generic Port Scan",
            "signature_id": 2024146
        })

        try:
            packet = IP(src=ip, dst=dest_ip)
            if attack["proto"] == "TCP":
                packet = packet / TCP(sport=RandShort(), dport=attack["port"], flags=attack["flags"])
            elif attack["proto"] == "UDP":
                packet = packet / UDP(sport=RandShort(), dport=attack["port"])

            print(f"Sending {attack['type']} packet from {ip} to {dest_ip}:{attack['port']}")
            for _ in range(3):
                send(packet, verbose=False)
                time.sleep(0.1)
            time.sleep(0.5)

            return {
                "status": "success",
                "message": f"Simulated {attack['type']} packet from {ip} to {dest_ip}:{attack['port']}"
            }
        except Exception as e:
            print(f"Scapy error for {ip}: {str(e)}. Falling back to mock alert.")
            mock_alert = {
                "event_type": "alert",
                "src_ip": ip,
                "src_port": random.randint(1024, 65535),
                "dest_ip": dest_ip,
                "dest_port": attack["port"],
                "proto": attack["proto"],
                "timestamp": datetime.now(pytz.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
                "alert": {
                    "signature": attack["signature"],
                    "category": attack["category"],
                    "severity": attack["severity"],
                    "signature_id": attack["signature_id"]
                }
            }
            try:
                with open(EVE_JSON_PATH, "a") as f:
                    f.write(json.dumps(mock_alert) + "\n")
                return {
                    "status": "success",
                    "message": f"Wrote mock {attack['type']} alert for {ip}"
                }
            except Exception as e:
                print(f"Error writing mock alert: {str(e)}")
                return {
                    "status": "error",
                    "message": f"Failed to simulate or write mock alert: {str(e)}"
                }
    except Exception as e:
        print(f"Error in simulate_suspicious_packet for {ip}: {str(e)}")
        return {
            "status": "error",
            "message": f"Failed to simulate packet: {str(e)}"
        }

# Background Monitoring
def monitor_suricata(interval: int = 10):
    while True:
        STATUS["running"] = is_suricata_running()
        STATUS["alerts_in_buffer"] = len(read_suricata_alerts())
        STATUS["blocked_ips"] = len(read_blocked_ips())
        print(f"Monitor: Suricata running={STATUS['running']}, alerts={STATUS['alerts_in_buffer']}, blocked_ips={STATUS['blocked_ips']}")
        try:
            run_ai_detect_script()
        except Exception as e:
            print(f"Error in periodic AI detection: {e}")
        time.sleep(interval)

@app.on_event("startup")
def start_monitoring():
    if not os.path.exists(IP_BLOCK_TXT):
        os.makedirs(os.path.dirname(IP_BLOCK_TXT), exist_ok=True)
        open(IP_BLOCK_TXT, "a").close()
        os.chmod(IP_BLOCK_TXT, 0o666)
    if not os.path.exists(EVE_JSON_PATH):
        os.makedirs(os.path.dirname(EVE_JSON_PATH), exist_ok=True)
        open(EVE_JSON_PATH, "a").close()
        os.chmod(EVE_JSON_PATH, 0o666)
    for script in [DYNAMIC_BLOCK_SCRIPT, DYNAMIC_UNBLOCK_SCRIPT, AI_DETECT_SCRIPT]:
        if os.path.exists(script):
            os.chmod(script, 0o755)
    t = Thread(target=monitor_suricata, args=(10,), daemon=True)
    t.start()

# Endpoints (only showing updated /api/threat_trends for brevity; others remain unchanged)
@app.options("/api/threat_trends")
async def options_threat_trends():
    headers = {
        "Access-Control-Allow-Origin": "http://localhost:3000",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "*",
        "Vary": "Origin",
    }
    return JSONResponse(status_code=200, headers=headers)

@app.get("/api/threat_trends", response_model=ThreatTrend)
def threat_trends():
    try:
        logs = read_suricata_alerts()
        print(f"Total logs read from {EVE_JSON_PATH}: {len(logs)}")
        filtered_logs = filter_logs_by_time(logs, "weekly")
        print(f"Filtered logs (weekly): {len(filtered_logs)}")

        alert_types = Counter(log.attack_type for log in filtered_logs)
        alert_types_list = [
            AlertType(name=attack_type, count=count)
            for attack_type, count in alert_types.most_common(8)
        ]
        countries = Counter(log.country for log in filtered_logs if log.country)
        countries_list = [
            CountryCount(name=country, count=count)
            for country, count in countries.most_common(8)
        ]
        reports_list = [
            AlertEntry(
                src_ip=log.src_ip,
                attack_type=log.attack_type,
                timestamp=log.timestamp,
                country=log.country,
                severity=log.severity,
                category=log.category
            )
            for log in filtered_logs[:50]
        ]

        print(f"Threat trends: {len(filtered_logs)} logs, {len(alert_types_list)} alert types, {len(countries_list)} countries, {len(reports_list)} reports")
        return ThreatTrend(
            alert_types=alert_types_list,
            countries=countries_list,
            reports=reports_list
        )
    except Exception as e:
        print(f"Error in threat_trends: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch threat trends: {str(e)}",
            headers={
                "Access-Control-Allow-Origin": "http://localhost:3000",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "*",
                "Vary": "Origin",
            },
        )

# Remaining endpoints (unchanged from your code)
@app.get("/api/system_health", response_model=SystemHealth)
def system_health():
    return get_system_health()

@app.get("/api/blocked_ips")
def blocked_ips(page: int = 1, per_page: int = 5):
    if page < 1 or per_page < 1:
        raise HTTPException(status_code=400, detail="Invalid page or per_page value")
    blocked_ips = read_blocked_ips()
    total_items = len(blocked_ips)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_ips = blocked_ips[start:end]
    return {
        "blocked_ips": paginated_ips,
        "total_items": total_items,
        "current_page": page,
        "per_page": per_page
    }

@app.post("/api/block_ip")
def block_ip(request: BlockIPRequest):
    if not is_valid_ip(request.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    blocked_ips = read_blocked_ips()
    if request.ip in blocked_ips:
        raise HTTPException(status_code=400, detail=f"IP {request.ip} is already blocked")
    blocked_ips.append(request.ip)
    write_blocked_ips(blocked_ips)
    STATUS["blocked_ips"] = len(blocked_ips)
    run_block_script()
    return {"status": "success", "message": f"IP {request.ip} blocked successfully"}

@app.post("/api/unblock_ip")
def unblock_ip(request: UnblockIPRequest):
    if not is_valid_ip(request.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    blocked_ips = read_blocked_ips()
    if request.ip not in blocked_ips:
        raise HTTPException(status_code=404, detail=f"IP {request.ip} is not blocked")
    blocked_ips.remove(request.ip)
    write_blocked_ips(blocked_ips)
    STATUS["blocked_ips"] = len(blocked_ips)
    run_unblock_script(request.ip)
    return {"status": "success", "message": f"IP {request.ip} unblocked successfully"}

@app.get("/api/suricata/alerts")
def suricata_alerts():
    alerts = read_suricata_alerts()
    return {"alerts": [a.dict() for a in alerts]}

@app.get("/api/suricata/statistics")
def suricata_statistics():
    merged_logs = read_merged_logs()
    eve_logs = read_suricata_alerts()
    alerts_by_category = {}
    for alert in eve_logs:
        category = alert.category or "Unknown"
        alerts_by_category[category] = alerts_by_category.get(category, 0) + 1
    top_signatures = {}
    for alert in eve_logs:
        signature = alert.attack_type or "Unknown"
        top_signatures[signature] = top_signatures.get(signature, 0) + 1
    top_signatures_list = [
        {"signature": k, "count": v} for k, v in sorted(top_signatures.items(), key=lambda x: x[1], reverse=True)
    ]
    return {
        "statistics": {
            "total_alerts": len(merged_logs) + len(eve_logs),
            "alerts_by_category": alerts_by_category,
            "top_signatures": top_signatures_list[:5]
        }
    }

@app.get("/api/dashboard_stats")
def dashboard_stats():
    merged_logs = read_merged_logs()
    eve_logs = read_suricata_alerts()
    return {
        "total_alerts": len(merged_logs) + len(eve_logs),
        "high_severity_alerts": len([l for l in merged_logs if l.anomaly and l.anomaly >= 0.8]),
        "recent_alerts": len(merged_logs[-5:]),
        "blocked_ips": len(read_blocked_ips()),
        "live_threat_count": len(eve_logs),
    }

@app.get("/api/live_threats")
def live_threats():
    logs = read_merged_logs() + [AlertEntry(**a.dict()) for a in read_suricata_alerts()]
    return {"status": "success", "malicious_ips": [l.dict() for l in logs]}

@app.get("/api/ip/search/{ip}")
def search_ip(ip: str):
    logs = read_merged_logs() + [AlertEntry(**a.dict()) for a in read_suricata_alerts()]
    results = [l.dict() for l in logs if l.src_ip == ip or l.dest_ip == ip]
    if not results:
        raise HTTPException(status_code=404, detail="IP not found in logs")
    return {"ip": ip, "logs": results}

@app.get("/api/vps/status")
def vps_status():
    installed = Path(SURICATA_PATH).exists()
    return {
        "suricata_status": {
            "running": STATUS["running"],
            "suricata_installed": installed,
            "eve_log_path": EVE_JSON_PATH if Path(EVE_JSON_PATH).exists() else None,
            "simulation_mode": not installed,
            "alerts_in_buffer": STATUS["alerts_in_buffer"],
            "blocked_ips": STATUS["blocked_ips"]
        }
    }

@app.post("/api/suricata/start")
def start_suricata(interface: str = "lo"):
    if is_suricata_running():
        return {"status": "success", "message": "Suricata already running."}
    try:
        subprocess.Popen([SURICATA_PATH, "-i", interface, "-c", "/etc/suricata/suricata.yaml", "-l", "/var/log/suricata/"])
        print(f"Started Suricata on interface {interface}")
        return {"status": "success", "message": f"Suricata started on interface {interface}"}
    except Exception as e:
        print(f"Error starting Suricata: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/suricata/stop")
def stop_suricata():
    stopped = False
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['cmdline'] and 'suricata' in ' '.join(proc.info['cmdline']):
                psutil.Process(proc.info['pid']).terminate()
                stopped = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return {"status": "success", "message": "Suricata stopped." if stopped else "Suricata was not running."}

@app.post("/api/suricata/rules/update")
def update_rules():
    try:
        subprocess.run(["sudo", "suricata-update"], check=True)
        subprocess.run(["sudo", "systemctl", "reload", "suricata"], check=True)
        print("Suricata rules updated successfully")
        return {"status": "success", "message": "Suricata rules updated successfully."}
    except subprocess.CalledProcessError as e:
        print(f"Error updating rules: {e.stderr}")
        raise HTTPException(
            status_code=500,
            detail=f"Error updating Suricata rules: {e.stderr}",
            headers={
                "Access-Control-Allow-Origin": "http://localhost:3000",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "*",
                "Vary": "Origin",
            },
        )

@app.get("/api/risk/top_risks")
def top_risks():
    alerts = read_suricata_alerts()
    ip_risk_data = {}
    for alert in alerts:
        for ip in [alert.src_ip, alert.dest_ip]:
            if ip not in ip_risk_data:
                geo = get_geo_data(ip)
                ip_risk_data[ip] = {
                    "ip": ip,
                    "latitude": geo["latitude"],
                    "longitude": geo["longitude"],
                    "country": geo["country"],
                    "alert_count": 0,
                    "last_seen": alert.timestamp,
                    "severity_sum": 0,
                    "category": alert.category or "Unknown"
                }
            ip_risk_data[ip]["alert_count"] += 1
            ip_risk_data[ip]["severity_sum"] += (5 - (alert.severity or 4))
            ip_risk_data[ip]["last_seen"] = max(ip_risk_data[ip]["last_seen"], alert.timestamp)
            ip_risk_data[ip]["category"] = alert.category or "Unknown"
    
    top_risks = []
    for ip, data in ip_risk_data.items():
        risk_score = calculate_risk_score(alerts, ip)
        top_risks.append(RiskEntry(
            ip=ip,
            latitude=data["latitude"],
            longitude=data["longitude"],
            country=data["country"],
            risk_score=risk_score,
            threat_level=get_threat_level(risk_score),
            last_seen=data["last_seen"],
            category=data["category"],
            alert_count=data["alert_count"]
        ))
    
    top_risks = sorted(top_risks, key=lambda x: x.risk_score, reverse=True)[:10]
    print(f"Returning {len(top_risks)} top risks")
    return {"top_risks": [r.dict() for r in top_risks]}

@app.get("/api/risk/statistics")
def risk_statistics():
    alerts = read_suricata_alerts()
    ip_risk_data = {}
    for alert in alerts:
        for ip in [alert.src_ip, alert.dest_ip]:
            if ip not in ip_risk_data:
                ip_risk_data[ip] = {"risk_score": calculate_risk_score(alerts, ip)}
    
    total_ips = len(ip_risk_data)
    average_risk_score = sum(d["risk_score"] for d in ip_risk_data.values()) / max(total_ips, 1)
    threat_levels = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
    for ip, data in ip_risk_data.items():
        threat_level = get_threat_level(data["risk_score"])
        threat_levels[threat_level] += 1
    
    print(f"Statistics: {total_ips} IPs, avg risk: {average_risk_score:.3f}")
    return Statistics(
        total_ips=total_ips,
        average_risk_score=round(average_risk_score, 3),
        threat_levels=threat_levels
    ).dict()

@app.get("/api/risk/analyze/{ip}")
def analyze_ip(ip: str):
    alerts = read_suricata_alerts()
    ip_alerts = [a for a in alerts if a.src_ip == ip or a.dest_ip == ip]
    if not ip_alerts:
        raise HTTPException(status_code=404, detail=f"No alerts found for IP {ip}")
    
    geo = get_geo_data(ip)
    risk_score = calculate_risk_score(alerts, ip)
    risk_factors = []
    categories = set(a.category for a in ip_alerts if a.category)
    for category in categories:
        cat_alerts = [a for a in ip_alerts if a.category == category]
        score = sum(5 - (a.severity or 4) for a in cat_alerts) / max(len(cat_alerts), 1) / 5
        risk_factors.append({
            "name": category,
            "description": f"Activity related to {category}",
            "score": round(score, 3),
            "confidence": random.uniform(0.7, 0.95)
        })
    
    suspicious_activities = [a.attack_type for a in ip_alerts]
    print(f"Analyzed IP {ip}: {len(ip_alerts)} alerts")
    return IPDetails(
        ip=ip,
        city=geo["city"],
        country=geo["country"],
        connection_count=len(ip_alerts),
        risk_score=risk_score,
        threat_level=get_threat_level(risk_score),
        risk_factors=risk_factors,
        suspicious_activities=suspicious_activities
    ).dict()

@app.post("/api/risk/simulate/{ip}")
def simulate_traffic(ip: str):
    if ip not in MOCK_GEO_DATA:
        print(f"Invalid IP {ip} for simulation")
        raise HTTPException(status_code=400, detail=f"IP {ip} not recognized in mock geo data")
    
    result = simulate_suspicious_packet(ip=ip, dest_ip="192.168.1.100")
    if result["status"] == "error":
        raise HTTPException(status_code=500, detail=result["message"])
    
    print(f"Simulation result for {ip}: {result['message']}")
    return {
        "status": "success",
        "message": result["message"]
    }

@app.get("/api/generate_report", response_model=ReportData)
def generate_report(type: str):
    if type not in ["daily", "weekly", "monthly"]:
        raise HTTPException(status_code=400, detail="Invalid report type")
    logs = read_suricata_alerts()
    filtered_logs = filter_logs_by_time(logs, type)
    blocked_ips = read_blocked_ips()
    total_alerts = len(filtered_logs)
    high_severity = len([log for log in filtered_logs if log.severity and log.severity <= 2])
    top_threats = Counter(log.attack_type for log in filtered_logs).most_common(5)
    print(f"Report {type}: {total_alerts} alerts, {high_severity} high severity, {len(blocked_ips)} blocked IPs")
    return ReportData(
        report_type=type,
        generated_at=datetime.now(pytz.UTC).isoformat(),
        total_alerts=total_alerts,
        high_severity=high_severity,
        blocked_ips=len(blocked_ips),
        top_threats=top_threats
    )
