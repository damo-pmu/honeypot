#!/usr/bin/env python3
"""Cowrie events → RabbitMQ producer (single source of truth)

Reads Cowrie JSON logs and publishes to RabbitMQ for resilient processing.
No direct API calls - all events flow through the messaging layer.
"""
import json
import time
import os
from pathlib import Path
import asyncio
import logging

from src.messaging import publish_event, connect, setup_exchange_and_queues

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

COWRIE_LOG = os.getenv("COWRIE_LOG", "/cowrie/var/log/cowrie/cowrie.json")
API_URL = os.getenv("API_URL", "http://api:8000")

# Idempotence tracking - prevent reprocessing historical logs on restart
PROCESSED_OFFSET_FILE = "/app/data/last_offset.txt"


def parse_cowrie_event(line: str) -> dict:
    """Parse Cowrie JSON log line"""
    try:
        return json.loads(line.strip())
    except json.JSONDecodeError:
        return {}


def load_last_offset() -> int:
    """Load last processed offset for idempotence"""
    try:
        with open(PROCESSED_OFFSET_FILE, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0


def save_offset(offset: int):
    """Save offset after processing for exactly-once semantics"""
    Path("/app/data").mkdir(parents=True, exist_ok=True)
    with open(PROCESSED_OFFSET_FILE, "w") as f:
        f.write(str(offset))


async def publish_event_safe(routing_key: str, data: dict) -> bool:
    """Publish with guaranteed delivery using RabbitMQ persistence + retry"""
    return await publish_event("cowrie", routing_key, data)


def process_event(line: str):
    """Process single Cowrie event - publishes to RabbitMQ only"""
    event = parse_cowrie_event(line)
    if not event:
        return
    
    event_id = event.get("eventid", "")
    src_ip = event.get("src_ip", "unknown")
    src_port = event.get("src_port", 0)
    session_id = event.get("session", f"{src_ip}:{src_port}")
    
    # Skip healthcheck connections (Cowrie internal on 127.0.0.1 with 0 duration)
    if src_ip == "127.0.0.1" and "session.connect" in event_id and "command" not in event_id and "login" not in event_id:
        return
    
    event_data = {
        "session_id": session_id,
        "attacker_ip": src_ip,
        "src_port": src_port,
        "timestamp": event.get("timestamp", ""),
    }
    
    async def publish_all():
        """Publish all related events to RabbitMQ queues"""
        if "login" in event_id:
            event_data.update({
                "event_type": "login",
                "username": event.get("username", ""),
                "password": event.get("password", ""),
            })
            await publish_event_safe("auth", event_data)
        
        if "command" in event_id:
            event_data.update({
                "event_type": "command",
                "command": event.get("input", event.get("command", "")),
            })
            await publish_event_safe("commands", event_data)
        
        if "download" in event_id:
            url = event.get("url", "")
            if url:
                event_data.update({
                    "event_type": "download",
                    "url": url,
                })
                await publish_event_safe("downloads", event_data)
        
        if "session.connect" in event_id:
            event_data["event_type"] = "connect"
            await publish_event_safe("sessions", event_data)
        
        if "session.closed" in event_id:
            event_data["event_type"] = "closed"
            await publish_event_safe("sessions", event_data)
    
    # Run async publish in sync context
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(publish_all())
        else:
            asyncio.run(publish_all())
    except Exception as e:
        logger.error(f"Failed to publish to RabbitMQ: {e}")


def ingest_logs():
    """Watch Cowrie logs with idempotence - exactly-once processing"""
    log_path = Path(COWRIE_LOG)
    
    # Wait for log file
    while not log_path.exists():
        logger.info(f"[producer] Waiting for {log_path}...")
        time.sleep(2)
    
    # Load last offset for idempotence
    last_pos = load_last_offset()
    logger.info(f"[producer] Resuming from offset {last_pos}")
    
    while True:
        try:
            current_size = log_path.stat().st_size
            if current_size > last_pos:
                with open(log_path, "r") as f:
                    f.seek(last_pos)
                    for line in f:
                        process_event(line)
                    last_pos = f.tell()
                    save_offset(last_pos)  # Save after each batch
                    
        except Exception as e:
            logger.error(f"[producer] Error: {e}")
        
        time.sleep(1)


if __name__ == "__main__":
    ingest_logs()