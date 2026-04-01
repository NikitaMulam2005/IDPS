import os
import glob
import json
import pandas as pd
import geoip2.database
import pyshark
import ipaddress
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from sklearn.preprocessing import StandardScaler

# ---------------- CONFIG ----------------
SURICATA_LOG = "/var/log/suricata/eve.json"
PCAP_FOLDER = "/home/nikitamulam2005/pcaps/"
GEO_DB = "/home/nikitamulam2005/IDPS/ip-blocker/datasets/geoip.mmdb"

AI_BLOCK_FILE = "/home/nikitamulam2005/IDPS/ip-blocker/datasets/ai_block.txt"
MERGED_FILE = "/home/nikitamulam2005/IDPS/ip-blocker/datasets/merged_logs.csv"

MAX_PACKETS_PER_PCAP = 2000  # Increased for richer stats

WHITELIST = {"127.0.0.1", "8.8.8.8", "1.1.1.1", "1.0.0.1"}

# High-risk countries (customize based on your threat intel)
HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "VN"}  # Example

COMMON_PORTS = {80, 443, 22, 53, 25, 3389}

# ---------------- Helper ----------------
def is_public_ipv4(ip):
    try:
        obj = ipaddress.ip_address(ip)
        return obj.version == 4 and not obj.is_private
    except:
        return False

def get_geo_info(ip, reader):
    try:
        response = reader.country(ip)
        return response.country.iso_code or "UNKNOWN"
    except:
        return "UNKNOWN"

# ---------------- Load Data ----------------
suricata_data = []
if os.path.exists(SURICATA_LOG):
    with open(SURICATA_LOG) as f:
        for line in f:
            try:
                log = json.loads(line)
                if log.get("event_type") in ["alert", "flow", "anomaly"]:
                    suricata_data.append({
                        "src_ip": log.get("src_ip"),
                        "dest_port": log.get("dest_port", 0),
                        "proto": log.get("proto", "NA"),
                        "attack_type": log.get("alert", {}).get("signature", "NA"),
                        "bytes": log.get("flow", {}).get("bytes_toserver", 0) + log.get("flow", {}).get("bytes_toclient", 0)
                    })
            except:
                continue

df_suri = pd.DataFrame(suricata_data)

# PCAP loading (same as before, but capture more fields if possible)
py_data = []
pcap_files = glob.glob(os.path.join(PCAP_FOLDER, "*.pcap"))
for pcap in pcap_files:
    try:
        cap = pyshark.FileCapture(pcap, only_summaries=True)
        for i, pkt in enumerate(cap):
            py_data.append({
                "src_ip": getattr(pkt, "source", None),
                "dest_port": int(getattr(pkt, "sport", 0)) if getattr(pkt, "sport", None) else 0,
                "proto": getattr(pkt, "protocol", "NA"),
                "attack_type": "NA",
                "bytes": 0  # Placeholder; enhance with full capture if needed
            })
            if i >= MAX_PACKETS_PER_PCAP:
                break
    except:
        continue

df_py = pd.DataFrame(py_data)
df = pd.concat([df_suri, df_py], ignore_index=True)

df.dropna(subset=["src_ip"], inplace=True)
df = df[df["src_ip"].apply(is_public_ipv4)]

if df.empty:
    print("[!] No valid public IPv4 data")
    exit()

# ---------------- GeoIP ----------------
geo_reader = geoip2.database.Reader(GEO_DB) if os.path.exists(GEO_DB) else None
if geo_reader:
    df["country"] = df["src_ip"].apply(lambda ip: get_geo_info(ip, geo_reader))

# ---------------- Feature Engineering (Improved) ----------------
df["proto_code"] = df["proto"].astype('category').cat.codes

grouped = df.groupby("src_ip").agg({
    "dest_port": ["count", "nunique"],
    "proto_code": "mean",
    "attack_type": lambda x: sum(1 for a in x if a != "NA"),  # Count of rule hits
    "bytes": "sum",  # Total bytes if available
    "country": "first"
}).reset_index()

grouped.columns = ["src_ip", "packet_count", "unique_ports", "proto_avg", 
                   "rule_hits", "total_bytes", "country"]

# Derived features
grouped["port_scan_ratio"] = grouped["unique_ports"] / (grouped["packet_count"] + 1e-5)
grouped["common_port_ratio"] = grouped["unique_ports"].apply(
    lambda x: sum(1 for p in COMMON_PORTS if p in range(1, int(x)+1)) / (x + 1)  # Fixed logic
)
grouped["avg_bytes_per_pkt"] = grouped["total_bytes"] / (grouped["packet_count"] + 1e-5)
grouped["high_risk_country"] = grouped["country"].isin(HIGH_RISK_COUNTRIES).astype(int)

# Port entropy approximation (higher = more random ports → suspicious)
if len(grouped) > 1:
    grouped["port_entropy"] = grouped["unique_ports"].apply(lambda x: np.log2(x + 1))

# ---------------- ML Model (Tuned) ----------------
features = grouped[[
    "packet_count", "unique_ports", "proto_avg", "port_scan_ratio",
    "common_port_ratio", "avg_bytes_per_pkt", "high_risk_country", "port_entropy"
]].fillna(0)

# Scale features (helps IsolationForest)
scaler = StandardScaler()
features_scaled = scaler.fit_transform(features)

clf = IsolationForest(
    contamination='auto',      # Better than fixed 0.02
    n_estimators=300,
    max_samples='auto',
    random_state=42,
    n_jobs=-1
)

grouped["anomaly_score"] = clf.fit_predict(features_scaled)  # -1 = anomaly
grouped["ml_score"] = -clf.decision_function(features_scaled)  # Higher = more anomalous (positive)

# ---------------- Risk Score (Improved) ----------------
grouped["risk_score"] = (
    0.25 * np.log1p(grouped["packet_count"]) +           # Log to handle skew
    0.25 * grouped["unique_ports"] +
    0.15 * grouped["port_scan_ratio"] +
    0.15 * (1 - grouped["common_port_ratio"]) +
    0.10 * grouped["ml_score"] +
    0.10 * grouped["high_risk_country"]
)

# Normalize to [0,1]
grouped["risk_score"] = (grouped["risk_score"] - grouped["risk_score"].min()) / \
                        (grouped["risk_score"].max() - grouped["risk_score"].min() + 1e-8)

# ---------------- Final Decision (More Balanced) ----------------
threshold = 0.55  # Tunable; start lower than 0.6, adjust based on your false positive tolerance

grouped["final_pred"] = (
    (grouped["anomaly_score"] == -1) |
    (grouped["rule_hits"] > 0) |
    (grouped["risk_score"] > threshold)
).astype(int)

# ---------------- Filter & Save ----------------
suspicious_ips = grouped[
    (grouped["final_pred"] == 1) & 
    (grouped["risk_score"] > 0.5)  # Softer for candidates
]["src_ip"].tolist()

suspicious_ips = [ip for ip in suspicious_ips if ip not in WHITELIST]

with open(AI_BLOCK_FILE, "w") as f:
    for ip in suspicious_ips:
        f.write(ip + "\n")

grouped.to_csv(MERGED_FILE, index=False)

# ---------------- Metrics ----------------
total_ips = len(grouped)
ml_anomalies = (grouped["anomaly_score"] == -1).sum()
rule_hits = (grouped["rule_hits"] > 0).sum()
final_blocks = len(suspicious_ips)

print("\n📊 MODEL PERFORMANCE SUMMARY:")
print(f"Total IPs analyzed: {total_ips}")
print(f"ML anomalies: {ml_anomalies}")
print(f"Rule detections: {rule_hits}")
print(f"Final blocked IPs: {final_blocks}")
print(f"Detection rate: {(final_blocks / total_ips) * 100:.2f}%")

# Hybrid metrics (use rule_hits as proxy label; fallback if zero)
y_true = (grouped["rule_hits"] > 0).astype(int)
y_pred = grouped["final_pred"]

print("\n📊 HYBRID METRICS:")
print("Accuracy:", accuracy_score(y_true, y_pred))
print("Precision:", precision_score(y_true, y_pred, zero_division=0))
print("Recall:", recall_score(y_true, y_pred, zero_division=0))
print("F1 Score:", f1_score(y_true, y_pred, zero_division=0))
print("\nClassification Report:\n", classification_report(y_true, y_pred, zero_division=0))

print("\n📊 Risk Score Stats:")
print(grouped["risk_score"].describe())

top_risky = grouped.sort_values(by="risk_score", ascending=False).head(15)
print("\n🔥 Top Risky IPs:")
print(top_risky[["src_ip", "risk_score", "ml_score", "rule_hits", "country"]])

print("\n🚨 Suspicious IPs to Block:")
for ip in suspicious_ips[:30]:
    print(ip)

print("\n✅ Processing complete!")
print("Tip: Tune 'threshold' (currently 0.55) and HIGH_RISK_COUNTRIES based on manual review of blocked IPs.")