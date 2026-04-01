#!/bin/bash
# Step 1: Run AI detection
python3 /home/nikitamulam2005/idps/ip-blocker/scripts/ai_detect.py

# Step 2: Apply dynamic blocking
bash /home/nikitamulam2005/idps/ip-blocker/scripts/dynamic_block.sh
