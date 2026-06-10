"""GeoIP service with MaxMind MMDB + ipapi.co fallback"""
import os
import logging
from typing import Optional, Dict, Any
from pathlib import Path
import asyncio

logger = logging.getLogger(__name__)

# Configuration
MMDB_PATH = os.getenv("MMDB_PATH", "/app/data/geolite2.mmdb")
IPAPI_URL = "https://ipapi.co/{ip}/json/"


def lookup_offline(ip: str) -> Optional[Dict[str, Any]]:
    """Lookup IP in local MaxMind database"""
    try:
        import geoip2.database
        if not Path(MMDB_PATH).exists():
            return None
        with geoip2.database.Reader(MMDB_PATH) as reader:
            response = reader.city(ip)
            return {
                "lat": float(response.location.latitude) if response.location.latitude else None,
                "lon": float(response.location.longitude) if response.location.longitude else None,
                "city": response.city.name,
                "country": response.country.iso_code,
                "country_name": response.country.name,
                "asn": response.traits.autonomous_system_number,
            }
    except Exception:
        return None


async def lookup_online(ip: str) -> Optional[Dict[str, Any]]:
    """Fallback to ipapi.co (rate limited but reliable)"""
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(IPAPI_URL.format(ip=ip), timeout=aiohttp.ClientTimeout(total=3)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "lat": data.get("latitude"),
                        "lon": data.get("longitude"),
                        "city": data.get("city"),
                        "country": data.get("country_code"),
                        "country_name": data.get("country_name"),
                        "asn": data.get("asn"),
                    }
    except Exception:
        pass
    return None


async def enrich_ip(ip: str) -> Dict[str, Any]:
    """Enrich IP with geolocation - tries offline first, then online fallback"""
    result = lookup_offline(ip)
    if not result:
        result = await lookup_online(ip)
    return result or {}


def enrich_ip_sync(ip: str) -> Dict[str, Any]:
    """Synchronous wrapper for enrich_ip"""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(enrich_ip(ip))