import os
import requests
from ipaddress import ip_address

# GeoIP enrichment module
# This implementation uses an external provider when the IP is public.
# In production, it can be replaced with MaxMind MMDB or a local geoip2 database.

def _is_public_ip(address: str) -> bool:
    try:
        parsed = ip_address(address)
        return not (
            parsed.is_private or
            parsed.is_loopback or
            parsed.is_unspecified or
            parsed.is_reserved or
            parsed.is_multicast
        )
    except ValueError:
        return False


def _normalize_asn(asn_raw: str | None) -> str:
    if not asn_raw:
        return "AS0"

    normalized = str(asn_raw).strip()
    if normalized.startswith("AS"):
        return normalized.split(" ")[0]
    return f"AS{normalized}" if normalized.isnumeric() else normalized


def enrich_ip(ip: str) -> dict:
    """Enrich IP with GeoIP data."""
    if not _is_public_ip(ip):
        return {
            "ip": ip,
            "country": "XX",
            "city": "Unknown",
            "asn": "AS0",
            "is_vpn": False,
            "reputation": "unknown",
        }

    provider = os.getenv("GEOIP_PROVIDER", "ipapi").strip().lower()
    if provider != "ipapi":
        provider = "ipapi"

    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=4)
        if response.status_code != 200:
            raise RuntimeError("GeoIP provider responded with non-200")
        data = response.json()
    except Exception:
        return {
            "ip": ip,
            "country": "XX",
            "city": "Unknown",
            "asn": "AS0",
            "is_vpn": False,
            "reputation": "unknown",
        }

    asn = _normalize_asn(data.get("asn") or data.get("org"))
    city = data.get("city") or "Unknown"
    country = data.get("country") or "XX"

    reputation = data.get("reputation", "unknown")
    if not isinstance(reputation, str):
        reputation = "unknown"

    return {
        "ip": ip,
        "country": country,
        "city": city,
        "asn": asn,
        "is_vpn": detect_vpn_or_tor(asn),
        "reputation": reputation,
    }


def detect_vpn_or_tor(asn: str) -> bool:
    """Simple VPN/Tor detection heuristic"""
    vpn_indicators = ["AS9", "AS16", "AS22", "AS30", "TOR", "VPN"]
    return any(ind in asn for ind in vpn_indicators)
