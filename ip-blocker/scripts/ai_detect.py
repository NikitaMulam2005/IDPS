import os
import glob
import json
import pandas as pd
import geoip2.database
import pyshark
import ipaddress

from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# ---------------- CONFIG ----------------
SURICATA_LOG = "/var/log/suricata/eve.json"
PCAP_FOLDER = "/home/nikitamulam2005/pcaps/"
GEO_DB = "/home/nikitamulam2005/IDPS/ip-blocker/datasets/geoip.mmdb"

AI_BLOCK_FILE = "/home/nikitamulam2005/IDPS/ip-blocker/datasets/ai_block.txt"
MERGED_FILE = "/home/nikitamulam2005/IDPS/ip-blocker/datasets/merged_logs.csv"

MAX_PACKETS_PER_PCAP = 1000

WHITELIST = {
    "127.0.0.1",
    "8.8.8.8",
    "1.1.1.1"
}

COMMON_PORTS = {80, 443, 22, 53}

# ---------------- Helper ----------------

def is_public_ipv4(ip):
    try:
        obj = ipaddress.ip_address(ip)
        return obj.version == 4 and not obj.is_private
    except:
        return False

# ---------------- Load Suricata ----------------

suricata_data = []

if os.path.exists(SURICATA_LOG):
    with open(SURICATA_LOG) as f:
        for line in f:
            try:
                log = json.loads(line)
                if log.get("event_type") in ["alert", "flow"]:
                    suricata_data.append({
                        "src_ip": log.get("src_ip"),
                        "dest_port": log.get("dest_port", 0),
                        "proto": log.get("proto", "NA"),
                        "attack_type": log.get("alert", {}).get("signature", "NA")
                    })
            except:
                continue

df_suri = pd.DataFrame(suricata_data)

# ---------------- Load PCAP ----------------

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
                "attack_type": "NA"
            })
            if i >= MAX_PACKETS_PER_PCAP:
                break
    except:
        continue

df_py = pd.DataFrame(py_data)

# ---------------- Merge ----------------

df = pd.concat([df_suri, df_py], ignore_index=True)

df.dropna(subset=["src_ip"], inplace=True)
df = df[df["src_ip"].apply(is_public_ipv4)]

if df.empty:
    print("[!] No valid data")
    exit()

# ---------------- Feature Engineering ----------------

df["proto_code"] = df["proto"].astype('category').cat.codes

grouped = df.groupby("src_ip").agg({
    "dest_port": ["count", "nunique"],
    "proto_code": "mean",
    "attack_type": lambda x: list(x)
})

grouped.columns = ["packet_count", "unique_ports", "proto_avg", "attack_list"]
grouped = grouped.reset_index()

# ---------------- Derived Features ----------------

grouped["port_scan_ratio"] = grouped["unique_ports"] / (grouped["packet_count"] + 1)

grouped["common_port_ratio"] = grouped["unique_ports"].apply(
    lambda x: len([p for p in COMMON_PORTS if p < x]) / (x + 1)
)

grouped["rule_pred"] = grouped["attack_list"].apply(
    lambda lst: 1 if any(a != "NA" for a in lst) else 0
)

# ---------------- ML Model ----------------

features = grouped[[
    "packet_count",
    "unique_ports",
    "proto_avg",
    "port_scan_ratio",
    "common_port_ratio"
]]

clf = IsolationForest(
    contamination=0.02,
    n_estimators=200,
    random_state=42
)

grouped["ml_pred"] = clf.fit_predict(features)
grouped["ml_pred"] = grouped["ml_pred"].apply(lambda x: 1 if x == -1 else 0)

# ---------------- Risk Score ----------------

grouped["risk_score"] = (
    grouped["packet_count"] * 0.3 +
    grouped["unique_ports"] * 0.3 +
    grouped["port_scan_ratio"] * 0.2 +
    (1 - grouped["common_port_ratio"]) * 0.2
)

grouped["risk_score"] = grouped["risk_score"] / grouped["risk_score"].max()

# ---------------- Final Decision ----------------

grouped["final_pred"] = (
    (grouped["ml_pred"] == 1) |
    (grouped["rule_pred"] == 1) |
    (grouped["risk_score"] > 0.6)
).astype(int)

# ---------------- Select IPs ----------------

suspicious_ips = grouped[
    (grouped["final_pred"] == 1) &
    (grouped["risk_score"] > 0.6)
]["src_ip"]

suspicious_ips = [
    ip for ip in suspicious_ips
    if ip not in WHITELIST
]

# ---------------- Save ----------------

with open(AI_BLOCK_FILE, "w") as f:
    for ip in suspicious_ips:
        f.write(ip + "\n")

grouped.to_csv(MERGED_FILE, index=False)

# ---------------- Metrics ----------------

total_ips = len(grouped)
ml_hits = grouped["ml_pred"].sum()
rule_hits = grouped["rule_pred"].sum()
final_hits = len(suspicious_ips)

print("\n📊 MODEL PERFORMANCE SUMMARY:")
print(f"Total IPs analyzed: {total_ips}")
print(f"ML anomalies: {ml_hits}")
print(f"Rule detections: {rule_hits}")
print(f"Final blocked IPs: {final_hits}")
print(f"Detection rate: {(final_hits / total_ips) * 100:.2f}%")

# Optional hybrid evaluation
grouped["label"] = grouped["rule_pred"]

y_true = grouped["label"]
y_pred = grouped["final_pred"]

print("\n📊 HYBRID METRICS (approx):")
print("Accuracy:", accuracy_score(y_true, y_pred))

# ---------------- Risk Insights ----------------

print("\n📊 Risk Score Stats:")
print(grouped["risk_score"].describe())

top_risky = grouped.sort_values(by="risk_score", ascending=False).head(10)

print("\n🔥 Top Risky IPs:")
print(top_risky[["src_ip", "risk_score", "ml_pred", "rule_pred"]])

print("\n🚨 Suspicious IPs:")
for ip in suspicious_ips[:20]:
    print(ip)

print("\n✅ Processing complete!")