# GeoIP enrichment module

# Mock provider for public repo (no API keys)
# In production, use geoip2 or MaxMind MMDB

MOCK_GEOIP = {
    "192.168.1.1": {"country": "US", "city": "San Francisco", "asn": "AS12345"},
    "10.0.0.1": {"country": "VN", "city": "Ho Chi Minh", "asn": "AS98765"},
    "172.16.0.1": {"country": "DE", "city": "Berlin", "asn": "AS54321"},
}

def enrich_ip(ip: str) -> dict:
    """Enrich IP with GeoIP data (mock for public)"""
    data = MOCK_GEOIP.get(ip, {"country": "XX", "city": "Unknown", "asn": "AS0"})
    return {
        "ip": ip,
        "country": data["country"],
        "city": data["city"],
        "asn": data["asn"],
        "is_vpn": data["asn"].startswith("AS9"),  # Simple heuristic
        "reputation": "unknown"
    }

def detect_vpn_or_tor(asn: str) -> bool:
    """Simple VPN/Tor detection heuristic"""
    # In production, use actual Tor exit list + VPN provider lists
    vpn_indicators = ["AS9", "AS16", "AS22", "AS30"]
    return any(ind in asn for ind in vpn_indicators)