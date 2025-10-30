#!/bin/bash

# Paths
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
AI_FILE="$BASE_DIR/datasets/ai_block.txt"
IPSET_NAME="known_bad_ips"

# Check if IP is provided
if [ -z "$1" ]; then
    echo "[!] No IP provided"
    exit 1
fi

IP="$1"

# Validate IP format (basic IPv4 check)
if ! [[ "$IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "[!] Invalid IP address: $IP"
    exit 1
fi

# Check if file exists
if [ ! -f "$AI_FILE" ]; then
    echo "[!] AI block file not found: $AI_FILE"
    exit 1
fi

# Remove IP from ipset
sudo ipset del "$IPSET_NAME" "$IP" -exist 2>/dev/null || {
    echo "[!] Failed to remove $IP from ipset $IPSET_NAME"
}

# Remove IP from ai_block.txt
if grep -Fx "$IP" "$AI_FILE" > /dev/null; then
    grep -Fxv "$IP" "$AI_FILE" > "${AI_FILE}.tmp" && mv "${AI_FILE}.tmp" "$AI_FILE"
    echo "[ok] Removed $IP from $AI_FILE"
else
    echo "[!] IP $IP not found in $AI_FILE"
fi

echo "[ok] IP $IP unblocked successfully"
