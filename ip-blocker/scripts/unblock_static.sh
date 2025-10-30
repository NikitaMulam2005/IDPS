#!/bin/bash
IPSET_NAME="known_bad_ips"
IPSET_CMD="/usr/sbin/ipset"
IPTABLES_CMD="/usr/sbin/iptables"

# Remove iptables rule
$IPTABLES_CMD -D INPUT -m set --match-set $IPSET_NAME src -j DROP 2>/dev/null || true
# Destroy ipset
$IPSET_CMD destroy $IPSET_NAME 2>/dev/null || true

echo "[OK] Removed ipset '$IPSET_NAME' and iptables rule"

