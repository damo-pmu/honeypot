#!/usr/bin/env python3
"""Test RabbitMQ messaging infrastructure"""
import asyncio
import json
import os
import sys

# Add project to path
sys.path.insert(0, "/app")

from src.messaging import publish_event, connect, setup_exchange_and_queues


async def test_publish_consume():
    """Test publish and consume cycle"""
    print("[test] Connecting to RabbitMQ...")
    channel = await connect()
    
    exchange, queues, dlq = await setup_exchange_and_queues(channel)
    print(f"[test] Exchange: cowrie.events, Queues: {list(queues.keys())}")
    
    # Test publish
    test_data = {
        "session_id": "test-session-001",
        "attacker_ip": "127.0.0.1",
        "event_type": "command",
        "command": "id"
    }
    
    result = await publish_event("test", "commands", test_data)
    print(f"[test] Publish result: {result}")
    
    print("[test] RabbitMQ infrastructure OK")


if __name__ == "__main__":
    asyncio.run(test_publish_consume())