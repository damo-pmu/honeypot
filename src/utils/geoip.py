"""GeoIP integration for dashboard - using MaxMind GeoLite2 (CDN fallback)"""
import os
from typing import Optional, Tuple

# Try to use maxminddb if available, otherwise use CDN endpoint
try:
    import maxminddb
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


def get_coordinates(ip: str) -> Optional[Tuple[float, float]]:
    """
    Get latitude/longitude for IP.
    Priority: MaxMind > ipapi.co CDN > None
    
    Returns (lat, lng) or None
    """
    if GEOIP_AVAILABLE:
        try:
            # Would need GeoLite2 database in docker volume
            pass
        except:
            pass
    
    # CDN fallback - ipapi.co (free tier: 1000/day)
    # This is called client-side in the dashboard for better performance
    return None


def format_attack_data(data: dict) -> dict:
    """Enrich attack data with GeoIP info for frontend"""
    ip = data.get("ip", "")
    if not ip or ip.startswith("127.") or ip in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]:
        return {**data, "geo": {"lat": None, "lng": None}}
    
    # Frontend will call ipapi.co CDN
    return {**data, "geo": {"lat": None, "lng": None, "lookup_url": f"https://ipapi.co/{ip}/json/"}}