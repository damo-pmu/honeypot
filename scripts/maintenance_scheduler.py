#!/usr/bin/env python3
"""Maintenance scheduler - runs retention jobs on configured intervals"""
import os
import time
import signal
import sys

# Import retention functions from script
sys.path.insert(0, '/app')
from scripts.db_maintenance import (
    apply_retention,
    cleanup_healthcheck_sessions,
    update_timestamps
)

# Configurable intervals (seconds)
RETENTION_INTERVAL = int(os.getenv('RETENTION_INTERVAL', 86400))  # daily
HEALTHCHECK_INTERVAL = int(os.getenv('HEALTHCHECK_INTERVAL', 3600))  # hourly

running = True

def signal_handler(signum, frame):
    global running
    running = False
    print(f"Received signal {signum}, shutting down...")

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    print(f"Maintenance scheduler started")
    print(f"  Retention: every {RETENTION_INTERVAL}s (days={RETENTION_INTERVAL//86400})")
    print(f"  Healthcheck cleanup: every {HEALTHCHECK_INTERVAL}s")
    
    last_retention = 0
    last_healthcheck = 0
    
    while running:
        now = time.time()
        
        if now - last_retention >= RETENTION_INTERVAL:
            print("Running retention cleanup...")
            apply_retention()
            last_retention = now
            
        if now - last_healthcheck >= HEALTHCHECK_INTERVAL:
            print("Running healthcheck cleanup...")
            cleanup_healthcheck_sessions()
            last_healthcheck = now
        
        time.sleep(10)  # Check every 10s
    
    print("Scheduler stopped")