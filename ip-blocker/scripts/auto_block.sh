#!/bin/bash
# Step 1: Run AI detection
python3 /home/ubuntu/idps/ip-blocker/scripts/ai_detect.py

# Step 2: Apply dynamic blocking
bash /home/ubuntu/idps/ip-blocker/scripts/dynamic_block.sh
