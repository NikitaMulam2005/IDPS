#!/bin/bash

set -e

# Paths
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
AI_FILE="$BASE_DIR/datasets/ai_block.txt"
IPSET_NAME="known_bad_ips"

# Check IP
if [ -z "$1" ]; then
    echo "[!] No IP provided"
    exit 1
fi

IP="$1"

# Validate IPv4
if ! [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "[!] Invalid IP address: $IP"
    exit 1
fi

# Check file exists
if [ ! -f "$AI_FILE" ]; then
    echo "[!] AI block file not found: $AI_FILE"
    exit 1
fi

echo "[+] Unblocking IP: $IP"

# Remove from ipset (no sudo)
if ipset list "$IPSET_NAME" 2>/dev/null | grep -q "$IP"; then
    ipset del "$IPSET_NAME" "$IP"
    echo "[ok] Removed $IP from ipset $IPSET_NAME"
else
    echo "[!] IP $IP not found in ipset"
fi

# Remove from file safely
TMP_FILE="${AI_FILE}.tmp"

grep -Fxv "$IP" "$AI_FILE" > "$TMP_FILE" || true
mv "$TMP_FILE" "$AI_FILE"

echo "[ok] Removed $IP from $AI_FILE"
echo "[ok] IP $IP unblocked successfully"
