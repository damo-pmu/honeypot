#!/usr/bin/env python3
"""Cowrie events → Honeypot API worker with IOC scanning and response engine"""
import json
import time
import os
from pathlib import Path
import requests
from typing import Optional, List

from src.messaging import publish_event, connect, setup_exchange_and_queues

API_URL = os.getenv("API_URL", "http://api:8000")
COWRIE_LOG = os.getenv("COWRIE_LOG", "/cowrie/var/log/cowrie/cowrie.json")

# Session tracking for response engine
session_commands: dict = {}

# RabbitMQ ready flag
rabbitmq_ready = False


def parse_cowrie_event(line: str) -> dict:
    """Parse Cowrie JSON log line"""
    try:
        event = json.loads(line.strip())
        return event
    except json.JSONDecodeError:
        return {}


def send_to_api(endpoint: str, data: dict) -> bool:
    """Send data to honeypot API"""
    try:
        # Fix: endpoint should match router paths (internal_router has NO prefix)
        r = requests.post(f"{API_URL}{endpoint}", json=data, timeout=5)
        return r.status_code in (200, 201)
    except requests.RequestException:
        return False


def scan_for_iocs(text: str) -> dict:
    """Extract IOCs from text (inline to avoid import issues)"""
    from src.analytics.ioc_scanner import scan_for_iocs as analytics_scan_for_iocs
    
    results = analytics_scan_for_iocs(text)
    return {
        "hashes": [ioc.value for ioc in results["hashes"]],
        "ips": [ioc.value for ioc in results["ips"]],
        "urls": [ioc.value for ioc in results["urls"]],
        "total": results.get("total", 0)
    }


def get_threat_class(commands: List[str]) -> str:
    """Quick threat classification - no LLM in hot path"""
    cmd_str = " ".join(commands).lower()
    
    if any(t in cmd_str for t in ["nmap", "masscan", "nikto", "sqlmap"]):
        return "AUTOMATED_SCANNER"
    elif any(t in cmd_str for t in ["wget", "curl"]) and "http" in cmd_str:
        return "MALWARE_DOWNLOAD"
    elif len(commands) > 5 and all(len(c) < 20 for c in commands):
        return "POSSIBLE_AI_AGENT"
    return "UNKNOWN"


def get_severity(command: str) -> int:
    """Calculate severity score for command (0-100)"""
    cmd = command.lower()
    if any(x in cmd for x in ["wget", "curl", "/dev/tcp", "nc "]):
        return 80
    if any(x in cmd for x in ["passwd", "shadow", "/etc/", "sqlmap"]):
        return 90
    if any(x in cmd for x in ["nmap", "masscan", "nikto"]):
        return 60
    return 30


def process_command_with_ioc(command: str, session_id: str, src_ip: str):
    """Process command and extract IOC data"""
    iocs = scan_for_iocs(command)
    
    for h in iocs.get("hashes", []):
        send_to_api("/ioc/store", {
            "ioc_type": "hash",
            "value": h,
            "related_session_id": session_id,
            "related_attacker_ip": src_ip
        })
    
    for ip in iocs.get("ips", []):
        send_to_api("/ioc/store", {
            "ioc_type": "ip",
            "value": ip,
            "related_session_id": session_id,
            "related_attacker_ip": src_ip
        })
    
    for url in iocs.get("urls", []):
        send_to_api("/ioc/store", {
            "ioc_type": "url",
            "value": url,
            "related_session_id": session_id,
            "related_attacker_ip": src_ip
        })


def to_rabbitmq(event_type: str, data: dict):
    """Publish event to RabbitMQ (non-blocking)"""
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(publish_event(event_type, event_type, data))
        else:
            asyncio.run(publish_event(event_type, event_type, data))
    except Exception as e:
        print(f"[worker] RabbitMQ publish error: {e}")


def process_event(line: str):
    """Process a single Cowrie event line"""
    global rabbitmq_ready
    
    event = parse_cowrie_event(line)
    if not event:
        return
    
    event_id = event.get("eventid", "")
    src_ip = event.get("src_ip", "unknown")
    src_port = event.get("src_port", 0)
    session_id = event.get("session", f"{src_ip}:{src_port}")
    
    # Skip healthcheck connections (Cowrie internal healthchecks on 127.0.0.1 with 0 duration)
    if src_ip == "127.0.0.1" and "session.connect" in event_id and "login" not in event_id and "command" not in event_id:
        return  # Skip pure connection events from localhost (healthchecks)
    
    if "login" in event_id:
        username = event.get("username", "")
        password = event.get("password", "")
        
        send_to_api("/attackers", {"ip": src_ip})
        send_to_api("/internal/sessions", {
            "session_id": session_id,
            "attacker_ip": src_ip,
            "protocol": "SSH"
        })
        
        # Log attack event to internal endpoint
        send_to_api("/events", {
            "session_id": session_id,
            "attacker_ip": src_ip,
            "protocol": "SSH",
            "attack_type": "BRUTE_FORCE",
            "payload": f"{username}:{password}",
            "severity": 70 if password else 50
        })
        
        # Publish to RabbitMQ for resilient processing
        to_rabbitmq("auth", {
            "session_id": session_id,
            "attacker_ip": src_ip,
            "username": username,
            "password": password,
            "event_type": "login"
        })
    
    elif "command" in event_id:
        command = event.get("input", event.get("command", ""))
        
        if session_id not in session_commands:
            session_commands[session_id] = []
        session_commands[session_id].append(command)
        interaction_count = len(session_commands[session_id])
        
        # Log command (existing endpoint)
        send_to_api("/commands", {
            "session_id": session_id,
            "command": command
        })
        
        process_command_with_ioc(command, session_id, src_ip)
        
        # Log attack to internal endpoint
        send_to_api("/events", {
            "session_id": session_id,
            "attacker_ip": src_ip,
            "protocol": "SSH",
            "attack_type": "COMMAND_EXECUTION",
            "payload": command[:500],
            "severity": get_severity(command)
        })
        
        # Publish to RabbitMQ
        to_rabbitmq("commands", {
            "session_id": session_id,
            "attacker_ip": src_ip,
            "command": command,
            "interaction_count": interaction_count
        })
        
        threat_class = get_threat_class(session_commands[session_id])
    
    elif "download" in event_id:
        url = event.get("url", "")
        if url:
            process_command_with_ioc(url, "download", src_ip)
            send_to_api("/events", {
                "session_id": session_id,
                "attacker_ip": src_ip,
                "protocol": "SSH",
                "attack_type": "MALWARE_DOWNLOAD",
                "payload": url,
                "severity": 95
            })
            
            to_rabbitmq("downloads", {
                "session_id": session_id,
                "attacker_ip": src_ip,
                "url": url
            })
    
    elif "session.connect" in event_id:
        send_to_api("/attackers", {"ip": src_ip})
        send_to_api("/internal/sessions", {
            "session_id": session_id,
            "attacker_ip": src_ip,
            "protocol": "SSH"
        })
        
        to_rabbitmq("sessions", {
            "session_id": session_id,
            "attacker_ip": src_ip,
            "protocol": "SSH",
            "event_type": "connect"
        })
    
    elif "session.closed" in event_id:
        # End session via internal endpoint
        try:
            requests.post(f"{API_URL}/internal/sessions/{session_id}/end")
        except:
            pass
        
        to_rabbitmq("sessions", {
            "session_id": session_id,
            "attacker_ip": src_ip,
            "event_type": "closed"
        })


def ingest_logs():
    """Watch Cowrie logs and ingest events with IOC scanning"""
    log_path = Path(COWRIE_LOG)
    
    print(f"[worker] Watching {log_path}")
    
    # Wait for log file
    while not log_path.exists():
        time.sleep(2)
    
    # Process existing content first (all historical events)
    last_size = 0
    last_pos = 0
    
    while True:
        try:
            current_size = log_path.stat().st_size
            if current_size > last_size:
                with open(log_path, "r") as f:
                    f.seek(last_pos)
                    for line in f:
                        process_event(line)
                    last_pos = f.tell()
                last_size = current_size
        except Exception as e:
            print(f"[worker] Error: {e}")
        
        time.sleep(1)


if __name__ == "__main__":
    ingest_logs()