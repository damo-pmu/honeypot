#!/usr/bin/env python3
"""
Damo Honeypot - IA Injection Detection Sandbox
Projet public - damo-pmu/honeypot

Toute injection est logguée mais jamais autorisée.
"""

import socket
import threading
import time
from datetime import datetime

def handle_connection(client_socket, addr):
    """Handle incoming connection with controlled /dev/urandom flood"""
    try:
        client_socket.send(b"[honeypot] Connection logged\n")
        time.sleep(1)
        
        # Controlled sample - max 1KB
        with open("/dev/urandom", "rb") as f:
            data = f.read(1024)
            client_socket.send(data)
        client_socket.close()
    except Exception:
        pass

if __name__ == "__main__":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 8080))
    server.listen(5)
    print("[honeypot] Running on 127.0.0.1:8080")