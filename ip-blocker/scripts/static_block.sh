#!/bin/bash
set -e

# Base directory
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INPUT_FILE="$BASE_DIR/datasets/firehol_level1.txt"
IPSET_NAME="known_bad_ips"

# Full paths for systemd
IPSET_CMD="/usr/sbin/ipset"
IPTABLES_CMD="/usr/sbin/iptables"

echo "[+] Removing old iptables rule (if exists)"
$IPTABLES_CMD -D INPUT -m set --match-set $IPSET_NAME src -j DROP 2>/dev/null || true

echo "[+] Destroying old ipset (if exists)"
$IPSET_CMD destroy $IPSET_NAME 2>/dev/null || true

echo "[+] Creating ipset $IPSET_NAME (hash:net for CIDRs)"
$IPSET_CMD create $IPSET_NAME hash:net -exist

echo "[+] Adding IPs/CIDRs from $INPUT_FILE..."
while IFS= read -r ip || [ -n "$ip" ]; do
    # Remove comments
    ip="${ip%%#*}"
    # Trim spaces
    ip="$(echo -n "$ip" | xargs)" || true
    # Skip empty lines
    [[ -z "$ip" ]] && continue
    # Validate IPv4 or CIDR
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]{1,2})?$ ]]; then
        $IPSET_CMD add $IPSET_NAME "$ip" -exist
    else
        echo "[!] Skipping invalid line: $ip"
    fi
done < "$INPUT_FILE"

# Ensure iptables rule exists
$IPTABLES_CMD -C INPUT -m set --match-set $IPSET_NAME src -j DROP 2>/dev/null \
    || $IPTABLES_CMD -I INPUT -m set --match-set $IPSET_NAME src -j DROP

echo "[OK] Loaded ipset '$IPSET_NAME'"
$IPSET_CMD list $IPSET_NAME | sed -n '1,5p'

