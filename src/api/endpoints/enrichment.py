"""GeoIP enrichment API endpoint"""
from fastapi import APIRouter

router = APIRouter(prefix="/enrichment", tags=["enrichment"])

@router.get("/ip")
def get_ip_enrichment(ip: str):
    """Get GeoIP data for IP (mock provider)"""
    from src.infrastructure.geoip.enrichment import enrich_ip, detect_vpn_or_tor
    
    data = enrich_ip(ip)
    data["is_vpn"] = detect_vpn_or_tor(data["asn"])
    return data