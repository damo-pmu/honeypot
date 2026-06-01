#!/usr/bin/env python3
"""Start honeypot API with dashboard"""
import os
import sys

# Ensure we're in the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["DASHBOARD_PASSWORD"] = "honeypot2024"
os.environ["HTTPS"] = "false"

import uvicorn
from app import app

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)