"""Threat intelligence feed collector"""
import asyncio
import csv
from io import StringIO
from typing import List, Dict
from datetime import datetime, timezone
import httpx

# Feed endpoints
FEEDS = {
    "urlhaus": "https://urlhaus.abuse.ch/downloads/csv/",
    "emerging_threats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "malware_domains": "https://mirror.cedia.org.ec/malwaredomains/justdomains",
}


async def fetch_urlhaus() -> List[Dict]:
    """Fetch URLHaus malicious URLs"""
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get(FEEDS["urlhaus"])
            if resp.status_code == 200:
                # Parse CSV
                lines = resp.text.strip().split('\n')
                reader = csv.DictReader(lines)
                return [
                    {
                        "ioc_type": "url",
                        "value": row.get("url", ""),
                        "threat": row.get("threat", "unknown"),
                        "tags": row.get("tags", ""),
                        "source": "urlhaus"
                    }
                    for row in reader
                    if row.get("url")
                ]
        return []
    except Exception as e:
        return [{"error": str(e), "source": "urlhaus"}]


async def fetch_compromised_ips() -> List[Dict]:
    """Fetch compromised IPs from Emerging Threats"""
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get(FEEDS["emerging_threats"])
            if resp.status_code == 200:
                ips = [
                    line.strip() 
                    for line in resp.text.split('\n') 
                    if line.strip() and not line.startswith('#')
                ]
                return [
                    {
                        "ioc_type": "ip",
                        "value": ip,
                        "threat": "compromised",
                        "source": "emerging_threats"
                    }
                    for ip in ips
                ]
        return []
    except Exception as e:
        return [{"error": str(e), "source": "emerging_threats"}]


async def fetch_all_feeds() -> Dict[str, List[Dict]]:
    """Fetch all threat feeds in parallel"""
    results = await asyncio.gather(
        fetch_urlhaus(),
        fetch_compromised_ips(),
        return_exceptions=True
    )
    
    return {
        "urlhaus": results[0] if not isinstance(results[0], Exception) else [],
        "emerging_threats": results[1] if not isinstance(results[1], Exception) else [],
    }


def store_feeds(feed_data: List[Dict]) -> int:
    """Store feed IOCs in database (placeholder for DB integration)"""
    # Would call create_ioc for each entry
    return len(feed_data)


async def collect_and_store():
    """Main feed collection function"""
    feeds = await fetch_all_feeds()
    
    total_stored = 0
    for source, iocs in feeds.items():
        if iocs and "error" not in iocs[0] if iocs else True:
            total_stored += store_feeds(iocs)
    
    return {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "total_iocs": total_stored,
        "sources": list(feeds.keys())
    }