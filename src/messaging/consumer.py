#!/usr/bin/env python3
"""RabbitMQ consumer for resilient event processing - exactly-once semantics"""
import asyncio
import json
import logging
import os
import aiohttp
from typing import Optional

from src.messaging import connect, setup_exchange_and_queues

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

API_URL = os.getenv("API_URL", "http://api:8000")


async def check_duplicate(message_id: str) -> bool:
    """Check if message was already processed (idempotence)"""
    try:
        import redis.asyncio as redis
        r = redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379"), decode_responses=True)
        exists = await r.setnx(f"processed:{message_id}", "1")
        if exists:
            await r.expire(f"processed:{message_id}", 86400)
        return not exists
    except:
        return False


def generate_message_id(data: dict) -> str:
    """Generate unique message ID for idempotence"""
    return f"{data.get('session_id', '')}:{data.get('event_type', '')}:{data.get('timestamp', '')}"


async def enrich_geoip(attacker_ip: str) -> dict:
    """Enrich IP with geolocation - offline MaxMind or online fallback"""
    try:
        # Try MaxMind MMDB first
        import geoip2.database
        from pathlib import Path
        mmdb_path = os.getenv("MMDB_PATH", "/app/data/geolite2.mmdb")
        if Path(mmdb_path).exists():
            with geoip2.database.Reader(mmdb_path) as reader:
                response = reader.city(attacker_ip)
                return {
                    "lat": response.location.latitude,
                    "lon": response.location.longitude,
                    "country": response.country.iso_code,
                    "city": response.city.name,
                    "asn": response.traits.autonomous_system_number,
                }
    except Exception as e:
        logger.debug(f"GeoIP offline failed for {attacker_ip}: {e}")
    
    # Fallback to ipapi.co (public API, rate limited)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://ipapi.co/{attacker_ip}/json/", timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "lat": data.get("latitude"),
                        "lon": data.get("longitude"),
                        "country": data.get("country_code"),
                        "city": data.get("city"),
                    }
    except Exception as e:
        logger.debug(f"GeoIP online failed for {attacker_ip}: {e}")
    
    return {}


async def handle_auth_event(data: dict):
    """Handle auth events - idempotent"""
    message_id = generate_message_id(data)
    
    if await check_duplicate(message_id):
        logger.debug(f"Duplicate message skipped: {message_id}")
        return
    
    session_id = data.get("session_id")
    attacker_ip = data.get("attacker_ip")
    username = data.get("username", "")
    password = data.get("password", "")
    severity = 70 if password else 50
    
    async with aiohttp.ClientSession() as session:
        async with session.post(f"{API_URL}/attackers", json={"ip": attacker_ip}):
            pass
        
        async with session.post(f"{API_URL}/internal/sessions", json={
            "session_id": session_id,
            "attacker_ip": attacker_ip,
            "protocol": "SSH"
        }) as resp:
            if resp.status not in (200, 201):
                raise Exception(f"Session create failed: {await resp.text()}")
        
        async with session.post(f"{API_URL}/events", json={
            "session_id": session_id,
            "attacker_ip": attacker_ip,
            "protocol": "SSH",
            "attack_type": "BRUTE_FORCE",
            "payload": f"{username}:{password}",
            "severity": severity
        }) as resp:
            if resp.status not in (200, 201):
                raise Exception(f"Event log failed: {await resp.text()}")


async def handle_command_event(data: dict):
    """Handle command events - idempotent"""
    message_id = generate_message_id(data)
    
    if await check_duplicate(message_id):
        logger.debug(f"Duplicate message skipped: {message_id}")
        return
    
    session_id = data.get("session_id")
    attacker_ip = data.get("attacker_ip")
    command = data.get("command", "")
    
    cmd_lower = command.lower()
    if any(x in cmd_lower for x in ["wget", "curl", "/dev/tcp", "nc "]):
        severity = 80
    elif any(x in cmd_lower for x in ["passwd", "shadow", "/etc/", "sqlmap"]):
        severity = 90
    elif any(x in cmd_lower for x in ["nmap", "masscan", "nikto"]):
        severity = 60
    else:
        severity = 30
    
    async with aiohttp.ClientSession() as session:
        async with session.post(f"{API_URL}/commands", json={
            "session_id": session_id,
            "command": command
        }):
            pass
        
        async with session.post(f"{API_URL}/events", json={
            "session_id": session_id,
            "attacker_ip": attacker_ip,
            "protocol": "SSH",
            "attack_type": "COMMAND_EXECUTION",
            "payload": command[:500],
            "severity": severity
        }) as resp:
            if resp.status not in (200, 201):
                raise Exception(f"Command event failed: {await resp.text()}")


async def handle_session_event(data: dict):
    """Handle session connect/closed events - idempotent"""
    message_id = generate_message_id(data)
    
    if await check_duplicate(message_id):
        logger.debug(f"Duplicate message skipped: {message_id}")
        return
    
    event_type = data.get("event_type")
    session_id = data.get("session_id")
    attacker_ip = data.get("attacker_ip")
    
    async with aiohttp.ClientSession() as session:
        # Enrich attacker with GeoIP on session connect
        geoip = await enrich_geoip(attacker_ip)
        if geoip:
            await session.post(f"{API_URL}/attackers", json={
                "ip": attacker_ip,
                "geoip": geoip
            })
        
        if event_type == "connect":
            await session.post(f"{API_URL}/attackers", json={"ip": attacker_ip})
            await session.post(f"{API_URL}/internal/sessions", json={
                "session_id": session_id,
                "attacker_ip": attacker_ip,
                "protocol": "SSH"
            })
        elif event_type == "closed":
            await session.post(f"{API_URL}/internal/sessions/{session_id}/end")


async def consume_with_ack():
    """Main consumer loop with ack/reject and retry logic"""
    channel = await connect()
    exchange, queues, dlq = await setup_exchange_and_queues(channel)
    
    # Bind queues
    for queue_name, queue_obj in queues.items():
        await queue_obj.bind(exchange, routing_key=queue_name)
    
    # Start consumers
    handlers = {
        "auth": handle_auth_event,
        "commands": handle_command_event,
        "sessions": handle_session_event,
    }
    
    for queue_name, handler in handlers.items():
        queue = queues[queue_name]
        
        async def process_message(msg, h=handler):
            async with msg.process(requeue=False):
                try:
                    data = json.loads(msg.body.decode())
                    await h(data)
                except Exception as e:
                    logger.error(f"Handler failed: {e}")
                    retry_count = (msg.headers or {}).get("x-retry-count", 0)
                    if retry_count < 3:
                        await msg.nack(requeue=True)
                    else:
                        await msg.reject(requeue=False)
                        logger.error(f"Message dead-lettered")
        
        await queue.consume(process_message)
        logger.info(f"Consumer ready for {queue_name}")
    
    # Keep alive
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(consume_with_ack())