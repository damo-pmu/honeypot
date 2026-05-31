#!/usr/bin/env python3
"""Cowrie events → Honeypot API worker with IOC scanning and response engine"""
import json
import time
import os
from pathlib import Path
import requests
from typing import Optional, List

API_URL = os.getenv("API_URL", "http://api:8000")
COWRIE_LOG = os.getenv("COWRIE_LOG", "/cowrie/var/log/cowrie.json")

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
    url_patterns = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
    
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


def trigger_decoy_response(session_id: str, attacker_ip: str, threat_class: str, interaction_count: int):
    """Trigger decoy response based on threat classification"""
    # Import here to avoid circular deps
    from src.response.router import decide_response, get_response_content
    
    decision = decide_response(
        session_id=session_id,
        attacker_ip=attacker_ip,
        threat_class=threat_class,
        confidence=0.8,
        interaction_count=interaction_count
    )
    
    if decision.response_type.value != "terminate" and decision.template_name:
        content = get_response_content(decision.template_name)
        if content:
            # Log response to API (for audit trail)
            send_to_api("/response/responses/log", {
                "session_id": session_id,
                "attacker_ip": attacker_ip,
                "template": decision.template_name,
                "content": content,
                "threat_class": threat_class
            })
            return content
    return None


def process_command_with_ioc(command: str, session_id: str, src_ip: str):
    """Process command and extract IOC data
    
    Args:
        command: Raw command from attacker
        session_id: Session identifier
        src_ip: Source IP of attacker
    """
    # Extract IOCs
    iocs = scan_for_iocs(command)
    
    if iocs["total"] > 0 if "total" in iocs else any(iocs.values()):
        # Send IOC data to API
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


def ingest_logs():
    """Watch Cowrie logs and ingest events with IOC scanning"""
    log_path = Path(COWRIE_LOG)
    
    print(f"[worker] Watching {log_path}")
    
    # Wait for log file
    while not log_path.exists():
        time.sleep(2)
    
    # Read existing + new lines
    with open(log_path, "r") as f:
        f.seek(0, 2)  # Seek to end for new events only
        
        while True:
            line = f.readline()
            if line:
                event = parse_cowrie_event(line)
                
                if "login" in event:
                    # New session started
                    src_ip = event.get("src_ip", "unknown")
                    src_port = event.get("src_port", 0)
                    session_id = f"{src_ip}:{src_port}"
                    
                    send_to_api("/attackers", {"ip": src_ip})
                    send_to_api("/sessions", {
                        "id": session_id,
                        "attacker_ip": src_ip,
                        "protocol": "SSH"
                    })
                
                elif "command" in event:
                    src_ip = event.get("src_ip", "unknown")
                    src_port = event.get("src_port", 0)
                    session_id = f"{src_ip}:{src_port}"
                    command = event["command"]
                    
                    # Track commands for threat classification
                    if session_id not in session_commands:
                        session_commands[session_id] = []
                    session_commands[session_id].append(command)
                    interaction_count = len(session_commands[session_id])
                    
                    # Send command
                    send_to_api("/commands", {
                        "session_id": session_id,
                        "command": command
                    })
                    
                    # Scan for IOCs in command
                    process_command_with_ioc(command, session_id, src_ip)
                    
                    # Trigger decoy response based on threat class
                    threat_class = get_threat_class(session_commands[session_id])
                    response = trigger_decoy_response(session_id, src_ip, threat_class, interaction_count)
                
                elif "download" in event:
                    # Handle file downloads
                    src_ip = event.get("src_ip", "unknown")
                    url = event.get("url", "")
                    if url:
                        process_command_with_ioc(url, "download", src_ip)
            
            time.sleep(0.1)


if __name__ == "__main__":
    ingest_logs()