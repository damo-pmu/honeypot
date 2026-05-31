#!/usr/bin/env python3
"""
Damo Honeypot - Telnet/SSH Impersonation Sandbox
Projet public - damo-pmu/honeypot

Impersonates a legacy telnet service to capture injection attempts.
All traffic logged, no system access granted.
"""

import socket
import threading
import select
from datetime import datetime

BANNER = b"\r\nLinux 5.4.0-xyz (localhost) (GNU/Linux 5.4.0-xyz)\r\n"

def handle_connection(client, addr):
    """Telnet impersonation with /dev/urandom flood on unexpected commands"""
    log_entry = f"[{datetime.now().isoformat()}] Connection from {addr[0]}:{addr[1]}\n"
    
    try:
        # Telnet-like banner
        client.send(BANNER)
        client.send(b"login: ")
        
        # Wait for input (simulating login)
        ready, _, _ = select.select([client], [], [], 30.0)
        if ready:
            user = client.recv(1024).decode(errors='replace').strip() + "\n"
            log_entry += f"User input: {user[:50]}\n"
            
            client.send(b"Password: ")
            
            # Trigger flood on any password attempt
            with open("/dev/urandom", "rb") as f:
                flood = f.read(512)
                client.send(flood)
                
        client.close()
    except Exception:
        pass
    
    # Log discretely
    with open("/tmp/honeypot.log", "a") as log:
        log.write(log_entry[:200])

if __name__ == "__main__":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 8080))
    server.listen(5)
    print("Service running on port 8080")