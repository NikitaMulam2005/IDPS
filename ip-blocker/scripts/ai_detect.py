import os
import glob
import json
import pandas as pd
import geoip2.database
import pyshark
from sklearn.ensemble import IsolationForest

# ---------------- CONFIG ----------------
SURICATA_LOG = "/var/log/suricata/eve.json"
PCAP_FOLDER = "/home/ubuntu/pcaps/"
GEO_DB = "/home/ubuntu/idps/ip-blocker/datasets/geoip.mmdb"

AI_BLOCK_FILE = "/home/ubuntu/idps/ip-blocker/datasets/ai_block.txt"
MERGED_FILE = "/home/ubuntu/idps/ip-blocker/datasets/merged_logs.csv"
PROCESSED_PCAPS = "/home/ubuntu/idps/ip-blocker/datasets/processed_pcaps.txt"

MAX_PACKETS_PER_PCAP = 1000

# Whitelist: IPs that should never be blocked
WHITELIST = {"127.0.0.1"}  # add your VPS IP, localhost, etc.

# ---------------- Load processed PCAPs ----------------
if os.path.exists(PROCESSED_PCAPS):
    with open(PROCESSED_PCAPS) as f:
        processed = set(f.read().splitlines())
else:
    processed = set()

# ---------------- Suricata logs ----------------
suricata_data = []
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
                    "attack_type": log.get("alert", {}).get("signature", "flow"),
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
    except FileNotFoundError:
        print(f"[!] PCAP file not found: {pcap}")

df_py = pd.DataFrame(py_data)

# ---------------- Merge logs ----------------
df = pd.concat([df_suri, df_py], ignore_index=True)
if df.empty:
    print("[!] No valid logs found. Exiting.")
    exit()

# ---------------- Remove duplicates ----------------
df.drop_duplicates(subset=["src_ip", "dest_ip", "dest_port", "proto", "attack_type", "timestamp"], inplace=True)

# ---------------- GeoIP lookup ----------------
reader = geoip2.database.Reader(GEO_DB)
countries = []
for ip in df["src_ip"]:
    try:
        r = reader.city(ip)
        countries.append(r.country.name)
    except:
        countries.append("Unknown")
df["country"] = countries
reader.close()

# ---------------- Prepare features for AI ----------------
df["proto_code"] = df["proto"].astype('category').cat.codes

# Exclude whitelist IPs from AI anomaly detection
df_ai = df[~df["src_ip"].isin(WHITELIST)].copy()
X = df_ai[["dest_port", "proto_code"]]

clf = IsolationForest(contamination=0.01, random_state=42)
df_ai["anomaly"] = clf.fit_predict(X)

# ---------------- Map anomalies back to main df ----------------
anomaly_map = df_ai.set_index("src_ip")["anomaly"].to_dict()
df["anomaly"] = df["src_ip"].map(anomaly_map)

# ---------------- Save suspicious IPs ----------------
suspicious_ips = df[df["anomaly"] == -1]["src_ip"].unique()
suspicious_ips = [ip for ip in suspicious_ips if ip not in WHITELIST]

with open(AI_BLOCK_FILE, "w") as f:
    for ip in suspicious_ips:
        f.write(ip + "\n")

print(f"[+] AI-detected suspicious IPs ({len(suspicious_ips)}):")
for ip in suspicious_ips:
    print(ip)

# ---------------- Save merged logs ----------------
df.to_csv(MERGED_FILE, index=False)

# ---------------- Save processed PCAPs ----------------
with open(PROCESSED_PCAPS, "w") as f:
    for pcap in processed:
        f.write(pcap + "\n")

print("[+] Processing complete!")

