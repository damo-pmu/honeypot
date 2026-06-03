#!/usr/bin/env python3
"""Cowrie events → Honeypot API worker with IOC scanning and response engine"""
import json
import time
import os
from pathlib import Path
import requests
from typing import Optional, List

API_URL = os.getenv("API_URL", "http://api:8000")
COWRIE_LOG = os.getenv("COWRIE_LOG", "/log/cowrie/cowrie.json")

# Session tracking for response engine
session_commands: dict = {}


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
        r = requests.post(f"{API_URL}{endpoint}", json=data, timeout=5)
        return r.status_code in (200, 201)
    except requests.RequestException:
        return False


def scan_for_iocs(text: str) -> dict:
    """Extract IOCs from text (inline to avoid import issues)"""
    import re
    
    hash_patterns = re.compile(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b')
    ip_patterns = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    url_patterns = re.compile(r'https?://[^\s<>\"{}|\\^`\[\]]+')
    
    return {
        "hashes": list(set(hash_patterns.findall(text))),
        "ips": list(set(ip_patterns.findall(text))),
        "urls": list(set(url_patterns.findall(text)))
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


def process_event(line: str):
    """Process a single Cowrie event line"""
    event = parse_cowrie_event(line)
    if not event:
        return
    
    event_id = event.get("eventid", "")
    src_ip = event.get("src_ip", "unknown")
    src_port = event.get("src_port", 0)
    session_id = f"{src_ip}:{src_port}"
    
    if "login" in event_id:
        # Login attempt - create attacker + session
        username = event.get("username", "")
        password = event.get("password", "")
        
        send_to_api("/attackers", {"ip": src_ip})
        send_to_api("/internal/sessions", {
            "session_id": session_id,
            "attacker_ip": src_ip,
            "protocol": "SSH"
        })
        
        # Log attack event to NEW internal endpoint
        send_to_api("/internal/events", {
            "session_id": session_id,
            "attacker_ip": src_ip,
            "protocol": "SSH",
            "attack_type": "BRUTE_FORCE",
            "payload": f"{username}:{password}",
            "severity": 70 if password else 50
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
        
        # Log attack to NEW internal endpoint
        send_to_api("/internal/events", {
            "session_id": session_id,
            "attacker_ip": src_ip,
            "protocol": "SSH",
            "attack_type": "COMMAND_EXECUTION",
            "payload": command[:500],
            "severity": get_severity(command)
        })
        
        threat_class = get_threat_class(session_commands[session_id])
        
    elif "download" in event_id:
        url = event.get("url", "")
        if url:
            process_command_with_ioc(url, "download", src_ip)
            send_to_api("/internal/events", {
                "session_id": session_id,
                "attacker_ip": src_ip,
                "protocol": "SSH",
                "attack_type": "MALWARE_DOWNLOAD",
                "payload": url,
                "severity": 95
            })
    
    elif "session.connect" in event_id:
        send_to_api("/attackers", {"ip": src_ip})
        send_to_api("/internal/sessions", {
            "session_id": session_id,
            "attacker_ip": src_ip,
            "protocol": "SSH"
        })
    
    elif "session.closed" in event_id:
        # End session via internal endpoint
        requests.post(f"{API_URL}/internal/sessions/{session_id}/end")


def ingest_logs():
    """Watch Cowrie logs and ingest events with IOC scanning"""
    log_path = Path(COWRIE_LOG)
    
    print(f"[worker] Watching {log_path}")
    
    # Wait for log file
    while not log_path.exists():
        time.sleep(2)
    
    # Process existing content first (all historical events)
    with open(log_path, "r") as f:
        for line in f:
            process_event(line)
        
        # Then watch for new events
        while True:
            line = f.readline()
            if line:
                process_event(line)
            time.sleep(0.1)


if __name__ == "__main__":
    ingest_logs()