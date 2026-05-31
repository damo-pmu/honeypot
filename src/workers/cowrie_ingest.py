#!/usr/bin/env python3
"""Cowrie events → Honeypot API worker"""
import json
import time
import os
from pathlib import Path
import requests

API_URL = os.getenv("API_URL", "http://api:8000")
COWRIE_LOG = os.getenv("COWRIE_LOG", "/cowrie/var/log/cowrie.json")

def parse_cowrie_event(line: str) -> dict:
    """Parse Cowrie JSON log line"""
    try:
        event = json.loads(line.strip())
        return event
    except json.JSONDecodeError:
        return {}

def send_to_api(endpoint: str, data: dict):
    """Send data to honeypot API"""
    try:
        r = requests.post(f"{API_URL}{endpoint}", json=data, timeout=5)
        return r.status_code == 201
    except requests.RequestException:
        return False

def ingest_logs():
    """Watch Cowrie logs and ingest events"""
    log_path = Path(COWRIE_LOG)
    
    print(f"[worker] Watching {log_path}")
    
    # Wait for log file
    while not log_path.exists():
        time.sleep(2)
    
    # Read existing + new lines
    with open(log_path, "r") as f:
        # Seek to end for new events only
        f.seek(0, 2)
        
        while True:
            line = f.readline()
            if line:
                event = parse_cowrie_event(line)
                if "login" in event:
                    send_to_api("/attackers", {"ip": event.get("src_ip", "unknown")})
                elif "command" in event:
                    send_to_api("/commands", {"command": event["command"]})
            time.sleep(0.1)

if __name__ == "__main__":
    ingest_logs()