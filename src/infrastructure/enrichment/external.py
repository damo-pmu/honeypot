"""External IOC enrichment providers.

This module supports multiple enrichment providers and local caching.
Rate limits are documented as 4 requests/minute per provider by default.
"""
import os
from typing import Optional, Dict
import httpx
import json

VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
from dataclasses import dataclass
from typing import Optional


@dataclass
class IOC:
    """IOC value object used by enrichment providers and tests

    Fields align with tests expectations: `source` defaults to 'scan',
    `confidence` defaults to 1.0.
    """
    ioc_type: str
    value: str
    confidence: float = 1.0
    source: str = "scan"
    context: Optional[str] = None
    source_event_id: Optional[str] = None


async def lookup_virustotal(ioc_value: str, ioc_type: str) -> Dict:
    """Query VirusTotal for IOC reputation
    
    Args:
        ioc_value: The IOC value to look up
        ioc_type: Type of IOC (hash, ip, url)
    
    Returns:
        Dict with reputation data or error
    """
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not configured", "source": "virustotal"}
    
    endpoint_map = {
        "hash": f"https://www.virustotal.com/api/v3/files/{ioc_value}",
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}",
        "url": f"https://www.virustotal.com/api/v3/urls/{ioc_value}"
    }
    
    if ioc_type not in endpoint_map:
        return {"error": f"Unsupported IOC type: {ioc_type}"}
    
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(endpoint_map[ioc_type], headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                # Extract key reputation metrics
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "source": "virustotal"
                }
            return {"error": f"HTTP {resp.status_code}", "source": "virustotal"}
    except Exception as e:
        return {"error": str(e), "source": "virustotal"}


async def lookup_abuseipdb(ip: str) -> Dict:
    """Query AbuseIPDB for IP reputation
    
    Args:
        ip: IP address to check
    
    Returns:
        Dict with abuse score and reports
    """
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not configured", "source": "abuseipdb"}
    
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params
            )
            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get("data", {})
                return {
                    "abuse_confidence": attrs.get("abuseConfidencePercentage", 0),
                    "country": attrs.get("countryCode", "?"),
                    "total_reports": attrs.get("totalReports", 0),
                    "is_whitelisted": attrs.get("isWhitelisted", False),
                    "source": "abuseipdb"
                }
            return {"error": f"HTTP {resp.status_code}", "source": "abuseipdb"}
    except Exception as e:
        return {"error": str(e), "source": "abuseipdb"}


async def lookup_urlhaus(url: str) -> Dict:
    """Check URL against URLHaus database
    
    Args:
        url: URL to check
    
    Returns:
        Dict with malware info if found
    """
    # Check against cached URLHaus data (updated daily)
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # URLHaus provides CSV - check if URL is present
            resp = await client.get("https://urlhaus.abuse.ch/downloads/csv/")
            if resp.status_code == 200:
                lines = resp.text.split("\n")
                for line in lines:
                    if url in line:
                        parts = line.split(",")
                        return {
                            "threat": parts[3] if len(parts) > 3 else "unknown",
                            "tags": parts[4] if len(parts) > 4 else "",
                            "source": "urlhaus"
                        }
                return {"found": False, "source": "urlhaus"}
            return {"error": f"HTTP {resp.status_code}", "source": "urlhaus"}
    except Exception as e:
        return {"error": str(e), "source": "urlhaus"}


async def enrich_ioc(ioc_value: str, ioc_type: str, use_cache: bool = True) -> Dict:
    """Multi-provider IOC enrichment with caching
    
    Args:
        ioc_value: IOC to enrich
        ioc_type: Type (hash, ip, url, domain)
        use_cache: Check Redis cache first (default True)
    
    Returns:
        Combined enrichment results
    """
    results = {}
    
    # Check cache first
    if use_cache:
        from src.infrastructure.enrichment.cache import cache
        cached = await cache.get_all_cached(ioc_value)
        if any(cached.values()):
            # Return cached if any found
            results = {k: v for k, v in cached.items() if v}
            if results:
                return {
                    "ioc": ioc_value,
                    "type": ioc_type,
                    "enrichments": results,
                    "cached": True
                }
    
    # Fresh lookups
    if ioc_type == "ip":
        ip_result = await lookup_abuseipdb(ioc_value)
        if use_cache and ip_result.get("abuse_confidence"):
            await cache.set_cached("abuseipdb", ioc_value, ip_result)
        results["abuseipdb"] = ip_result
        
        vt_result = await lookup_virustotal(ioc_value, "ip")
        if use_cache and vt_result.get("malicious") is not None:
            await cache.set_cached("virustotal", ioc_value, vt_result)
        results["virustotal"] = vt_result
        
    elif ioc_type == "hash":
        result = await lookup_virustotal(ioc_value, "hash")
        if use_cache and result.get("malicious") is not None:
            await cache.set_cached("virustotal", ioc_value, result)
        results["virustotal"] = result
        
    elif ioc_type == "url":
        vt_result = await lookup_virustotal(ioc_value, "url")
        if use_cache and vt_result.get("malicious") is not None:
            await cache.set_cached("virustotal", ioc_value, vt_result)
        results["virustotal"] = vt_result
        
        uh_result = await lookup_urlhaus(ioc_value)
        if use_cache and uh_result.get("threat"):
            await cache.set_cached("urlhaus", ioc_value, uh_result)
        results["urlhaus"] = uh_result
    else:
        return {
            "ioc": ioc_value,
            "type": ioc_type,
            "error": f"Unsupported type: {ioc_type}",
            "enrichments": {},
            "cached": False
        }
    
    return {
        "ioc": ioc_value,
        "type": ioc_type,
        "enrichments": results,
        "cached": False
    }