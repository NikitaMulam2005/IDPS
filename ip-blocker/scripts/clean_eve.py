#!/usr/bin/env python3
import json

# Paths
input_file = "/var/log/suricata/eve.json"
output_file = "/home/ubuntu/idps/ip-blocker/datasets/eve_clean.jsonl"

alert_count = 0

with open(input_file, 'r', encoding='utf-8') as infile, \
     open(output_file, 'w', encoding='utf-8') as outfile:

    for line in infile:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            # Keep only events with "alert" key
            if "alert" in obj:
                json.dump(obj, outfile)
                outfile.write("\n")
                alert_count += 1
        except json.JSONDecodeError:
            continue  # skip malformed lines

print(f"Total Suricata alert logs: {alert_count}")
print(f"Saved alerts to: {output_file}")

