#!/usr/bin/env python3
"""Start all honeypot services without Docker on OCI"""
import os
import sys
import subprocess
import signal
import time
import threading

# Configuration
os.environ.setdefault('DASHBOARD_PASSWORD', 'honeypot2024')
os.environ.setdefault('HTTPS', 'false')

services = {}

def start_api():
    """Start FastAPI on port 8000"""
    print("[API] Starting FastAPI on 0.0.0.0:8000...")
    proc = subprocess.Popen(
        ['python3', '-m', 'uvicorn', 'app:app', '--host', '0.0.0.0', '--port', '8000'],
        cwd='/home/ubuntu/test-honeypot'
    )
    return proc

def start_cowrie():
    """Start Cowrie SSH/Telnet honeypot"""
    print("[Cowrie] Starting on 2222/23...")
    proc = subprocess.Popen(
        ['python3', 'cowrie', 'start', '-q'],
        cwd='/home/ubuntu/test-honeypot/src/cowrie'
    )
    return proc

def start_worker():
    """Start background worker for events"""
    print("[Worker] Starting event processor...")
    proc = subprocess.Popen(
        ['python3', '-m', 'src.workers.cowrie_ingest'],
        cwd='/home/ubuntu/test-honeypot'
    )
    return proc

def start_postgres():
    """Start PostgreSQL (if available)"""
    print("[PostgreSQL] Starting on 5432...")
    proc = subprocess.Popen(
        ['postgres', '-D', '/var/lib/postgresql/data'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return proc

def signal_handler(signum, frame):
    """Graceful shutdown"""
    print("\nShutting down services...")
    for name, proc in services.items():
        if proc.poll() is None:
            print(f"  Killing {name}...")
            proc.terminate()
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start services
    services['api'] = start_api()
    time.sleep(2)  # Wait for API to be ready
    
    services['worker'] = start_worker()
    services['cowrie'] = start_cowrie()
    
    print("\n✅ All services started")
    print("   API: http://localhost:8000")
    print("   SSH: port 2222")
    print("   Dashboard: http://localhost:8000/dashboard/")
    
    # Keep alive
    try:
        while True:
            time.sleep(60)
            for name, proc in services.items():
                if proc.poll() is not None:
                    print(f"[WARN] {name} exited with code {proc.returncode}")
    except KeyboardInterrupt:
        signal_handler(0, None)