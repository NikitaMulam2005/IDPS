#!/bin/bash
set -e

# === CONFIGURATION ===
RULE_GROUP_NAME="BlockedIPs-chunk-aa"
REGION="us-west-2"
NEW_IPS_FILE="/home/ubuntu/idps/ip-blocker/datasets/ai_block.txt"
TEMP_CURRENT="/tmp/current_rules.json"
TEMP_UPDATED="/tmp/updated_rules.json"

# === FUNCTIONS ===
check_dns_and_fix() {
  echo "[+] Checking DNS resolution..."
  if ! ping -c1 -W2 network-firewall.${REGION}.amazonaws.com &>/dev/null; then
    echo "[!] DNS resolution failed. Applying temporary Google DNS fix..."
    echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" | sudo tee /etc/resolv.conf >/dev/null
    echo "[+] DNS configuration updated temporarily."
  else
    echo "[+] DNS resolution working fine."
  fi
}

# === MAIN ===
echo "=== AWS Network Firewall Rule Group Updater ==="
check_dns_and_fix

echo "[+] Fetching current rule group..."
aws network-firewall describe-rule-group \
  --rule-group-name "$RULE_GROUP_NAME" \
  --type STATELESS \
  --region "$REGION" \
  --query 'RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules' \
  --output json > "$TEMP_CURRENT"

echo "[+] Reading new IPs from $NEW_IPS_FILE..."
# Convert IP list to valid JSON array of {AddressDefinition: "ip"}
NEW_IPS_JSON=$(awk '!/^#/ && NF {print "{\"AddressDefinition\":\""$0"\"}"}' "$NEW_IPS_FILE" | jq -s '.')

if [ -z "$NEW_IPS_JSON" ] || [ "$NEW_IPS_JSON" = "[]" ]; then
  echo "[-] No valid IPs found in $NEW_IPS_FILE!"
  exit 1
fi

echo "[+] Building new firewall rule definition..."
jq --argjson new "$NEW_IPS_JSON" '
{
  RulesSource: {
    StatelessRulesAndCustomActions: {
      StatelessRules: [
        {
          RuleDefinition: {
            MatchAttributes: {
              Sources: $new
            },
            Actions: ["aws:drop"]
          },
          Priority: 1
        }
      ]
    }
  }
}
' > "$TEMP_UPDATED" <<< "[]"

echo "[+] Fetching update token..."
UPDATE_TOKEN=$(aws network-firewall describe-rule-group \
  --rule-group-name "$RULE_GROUP_NAME" \
  --type STATELESS \
  --region "$REGION" \
  --query 'UpdateToken' \
  --output text)

echo "[+] Updating AWS Network Firewall rule group..."
aws network-firewall update-rule-group \
  --rule-group-name "$RULE_GROUP_NAME" \
  --type STATELESS \
  --region "$REGION" \
  --update-token "$UPDATE_TOKEN" \
  --rule-group file://"$TEMP_UPDATED"

echo "[✔] Firewall rule group '$RULE_GROUP_NAME' successfully updated with new IPs from '$NEW_IPS_FILE'."

