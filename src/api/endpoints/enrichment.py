"""GeoIP and IOC enrichment API endpoints"""
from fastapi import APIRouter
from typing import Dict

router = APIRouter(prefix="/enrichment", tags=["enrichment"])


@router.get("/ip")
def get_ip_enrichment(ip: str):
    """Get GeoIP data for IP (mock provider)"""
    from src.infrastructure.geoip.enrichment import enrich_ip, detect_vpn_or_tor
    
    data = enrich_ip(ip)
    data["is_vpn"] = detect_vpn_or_tor(data["asn"])
    return data


@router.get("/ioc/{ioc_value}")
async def lookup_ioc(ioc_value: str, ioc_type: str):
    """Multi-provider IOC lookup (VirusTotal, AbuseIPDB, URLHaus)"""
    from src.infrastructure.enrichment.external import enrich_ioc
    return await enrich_ioc(ioc_value, ioc_type)


@router.get("/ip/reputation/{ip}")
async def get_ip_reputation(ip: str):
    """Get IP reputation from AbuseIPDB"""
    from src.infrastructure.enrichment.external import lookup_abuseipdb
    return await lookup_abuseipdb(ip)


@router.get("/url/check")
async def check_url(url: str):
    """Check URL against threat feeds"""
    from src.infrastructure.enrichment.external import lookup_virustotal, lookup_urlhaus
    vt = await lookup_virustotal(url, "url")
    uh = await lookup_urlhaus(url)
    return {"virustotal": vt, "urlhaus": uh}


@router.get("/hash/{hash_value}")
async def check_hash(hash_value: str):
    """Check file hash reputation"""
    from src.infrastructure.enrichment.external import lookup_virustotal
    return await lookup_virustotal(hash_value, "hash")