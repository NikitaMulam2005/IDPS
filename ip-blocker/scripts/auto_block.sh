#!/bin/bash

# Activate virtual environment
source /home/nikitamulam2005/IDPS/ip-blocker/venv/bin/activate

# Step 1: Run AI detection
/home/nikitamulam2005/IDPS/ip-blocker/venv/bin/python3 /home/nikitamulam2005/IDPS/ip-blocker/scripts/ai_detect.py

# Step 2: Apply dynamic blocking
/bin/bash /home/nikitamulam2005/IDPS/ip-blocker/scripts/dynamic_block.sh
