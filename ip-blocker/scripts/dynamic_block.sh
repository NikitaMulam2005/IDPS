#!/bin/bash

# Paths
BASE_DIR="/home/nikitamulam2005/IDPS/ip-blocker"
AI_FILE="$BASE_DIR/datasets/ai_block.txt"
IPSET_NAME="known_bad_ips"

# Check if file exists
if [ ! -f "$AI_FILE" ]; then
    echo "[!] AI block file not found: $AI_FILE"
    exit 1
fi

# Ensure ipset exists
ipset list $IPSET_NAME &>/dev/null || ipset create $IPSET_NAME hash:net

# Add each AI-detected IP to ipset
echo "[+] Adding AI-detected IPs to ipset..."
while IFS= read -r ip || [ -n "$ip" ]; do
    ip="${ip%%#*}"                 # remove comments
    ip="$(echo -n "$ip" | xargs)"  # trim spaces
    [[ -z "$ip" ]] && continue

    ipset add $IPSET_NAME "$ip" -exist
done < "$AI_FILE"

# Ensure iptables DROP rule exists
iptables -C INPUT -m set --match-set $IPSET_NAME src -j DROP 2>/dev/null \
  || iptables -I INPUT -m set --match-set $IPSET_NAME src -j DROP

echo "[ok] AI-detected IPs added to $IPSET_NAME and iptables."
