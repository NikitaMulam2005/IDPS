import os
import glob
import json
import pandas as pd
import geoip2.database
import pyshark
import ipaddress

from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report

# ---------------- CONFIG ----------------
SURICATA_LOG = "/var/log/suricata/eve.json"
PCAP_FOLDER = "/home/nikitamulam2005/pcaps/"
GEO_DB = "/home/nikitamulam2005/IDPS/ip-blocker/datasets/geoip.mmdb"

AI_BLOCK_FILE = "/home/nikitamulam2005/IDPS/ip-blocker/datasets/ai_block.txt"
MERGED_FILE = "/home/nikitamulam2005/IDPS/ip-blocker/datasets/merged_logs.csv"
PROCESSED_PCAPS = "/home/nikitamulam2005/IDPS/ip-blocker/datasets/processed_pcaps.txt"

MAX_PACKETS_PER_PCAP = 1000
WHITELIST = {"127.0.0.1"}

# ---------------- Helper Functions ----------------

def is_public(ip):
    try:
        return not ipaddress.ip_address(ip).is_private
    except:
        return False

# ---------------- Load processed PCAPs ----------------
processed = set()
if os.path.exists(PROCESSED_PCAPS):
    with open(PROCESSED_PCAPS) as f:
        processed = set(f.read().splitlines())

# ---------------- Suricata logs ----------------
suricata_data = []
if os.path.exists(SURICATA_LOG):
    with open(SURICATA_LOG) as f:
        for line in f:
            try:
                log = json.loads(line)
                if log.get("event_type") in ["alert", "flow"]:
                    suricata_data.append({
                        "src_ip": log.get("src_ip"),
                        "dest_ip": log.get("dest_ip"),
                        "dest_port": log.get("dest_port", 0),
                        "proto": log.get("proto", "NA"),
                        "attack_type": log.get("alert", {}).get("signature", "NA"),
                        "timestamp": log.get("timestamp")
                    })
            except:
                continue

df_suri = pd.DataFrame(suricata_data)

# ---------------- PyShark logs ----------------
py_data = []
pcap_files = sorted(glob.glob(os.path.join(PCAP_FOLDER, "*.pcap")))
new_pcaps = [p for p in pcap_files if p not in processed]

for pcap in new_pcaps:
    try:
        cap = pyshark.FileCapture(pcap, only_summaries=True)
        for i, pkt in enumerate(cap):
            py_data.append({
                "src_ip": getattr(pkt, "source", None),
                "dest_ip": getattr(pkt, "destination", None),
                "dest_port": int(getattr(pkt, "sport", 0)) if getattr(pkt, "sport", None) else 0,
                "proto": getattr(pkt, "protocol", "NA"),
                "attack_type": "NA",
                "timestamp": getattr(pkt, "time", None)
            })
            if i + 1 >= MAX_PACKETS_PER_PCAP:
                break
        processed.add(pcap)
    except Exception as e:
        print(f"[!] Error processing {pcap}: {e}")

df_py = pd.DataFrame(py_data)

# ---------------- Merge logs ----------------
df = pd.concat([df_suri, df_py], ignore_index=True)

if df.empty:
    print("[!] No valid logs found. Exiting.")
    exit()

# ---------------- Clean data ----------------
df.dropna(subset=["src_ip", "dest_ip"], inplace=True)
df.drop_duplicates(inplace=True)

# ---------------- GeoIP (safe) ----------------
reader = geoip2.database.Reader(GEO_DB)
geo_cache = {}

def get_country(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    try:
        if not ip:
            geo_cache[ip] = "Unknown"
        elif ipaddress.ip_address(ip).is_private:
            geo_cache[ip] = "Private"
        else:
            response = reader.city(ip)
            geo_cache[ip] = response.country.name if response.country.name else "Unknown"
    except:
        geo_cache[ip] = "Unknown"
    return geo_cache[ip]

df["country"] = df["src_ip"].apply(get_country)
reader.close()

# ---------------- Feature Engineering ----------------
df["proto_code"] = df["proto"].astype('category').cat.codes

# Proper labels (IMPORTANT FIX)
df["label"] = df["attack_type"].apply(lambda x: 0 if x == "NA" else 1)

df["packet_count"] = df.groupby("src_ip")["src_ip"].transform("count")
df["unique_ports"] = df.groupby("src_ip")["dest_port"].transform("nunique")
df["alert_count"] = df.groupby("src_ip")["label"].transform("sum")

# ---------------- AI Model ----------------
df_ai = df[~df["src_ip"].isin(WHITELIST)].copy()

X = df_ai[[
    "dest_port",
    "proto_code",
    "packet_count",
    "unique_ports",
    "alert_count"
]]

clf = IsolationForest(contamination=0.1, random_state=42)
df_ai["anomaly"] = clf.fit_predict(X)

df_ai["pred"] = df_ai["anomaly"].apply(lambda x: 1 if x == -1 else 0)

# ---------------- Merge predictions ----------------
df = df.merge(df_ai[["src_ip", "pred"]], on="src_ip", how="left")
df["pred"] = df["pred"].fillna(0)

# ---------------- Hybrid Detection ----------------
df["final_pred"] = ((df["label"] == 1) | (df["pred"] == 1)).astype(int)

# ---------------- Evaluation (FIXED) ----------------
y_true = df["label"]
y_pred = df["final_pred"]

print("\n📊 FINAL HYBRID MODEL PERFORMANCE:")
print("Accuracy:", accuracy_score(y_true, y_pred))
print("Precision:", precision_score(y_true, y_pred, zero_division=0))
print("Recall:", recall_score(y_true, y_pred, zero_division=0))
print("F1 Score:", f1_score(y_true, y_pred, zero_division=0))

print("\n📊 Classification Report:")
print(classification_report(y_true, y_pred, zero_division=0))

# ---------------- Filter only PUBLIC IPs ----------------
suspicious_ips = df[df["final_pred"] == 1]["src_ip"].unique()

suspicious_ips = [
    ip for ip in suspicious_ips
    if is_public(ip) and ip not in WHITELIST
]

# ---------------- Save suspicious IPs ----------------
with open(AI_BLOCK_FILE, "w") as f:
    for ip in suspicious_ips:
        f.write(ip + "\n")

print(f"\n🚨 Public Suspicious IPs ({len(suspicious_ips)}):")
for ip in suspicious_ips:
    print(ip)

# ---------------- Save logs ----------------
df.to_csv(MERGED_FILE, index=False)

# ---------------- Save processed PCAPs ----------------
with open(PROCESSED_PCAPS, "w") as f:
    for p in processed:
        f.write(p + "\n")

print("\n✅ Processing complete!") 

