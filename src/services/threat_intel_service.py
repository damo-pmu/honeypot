"""Threat Intelligence Enrichment Service - Background enrichment of IOCs"""
import asyncio
import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import aiohttp

# API keys from environment
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
GREYNOISE_KEY = os.getenv("GREYNOISE_API_KEY")
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
OTX_KEY = os.getenv("OTX_API_KEY")


@dataclass
class ThreatIntelResult:
    """Enrichment result for an IOC"""
    value: str
    type: str
    reputation_score: int = 0
    malicious_count: int = 0
    tags: List[str] = None
    source: str = ""
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


class ThreatIntelService:
    """
    Enrich IOCs with external threat intelligence feeds.
    Non-blocking background enrichment via aiohttp.
    """
    
    TIMEOUT = aiohttp.ClientTimeout(total=10)
    
    def __init__(self):
        self.session = aiohttp.ClientSession(timeout=self.TIMEOUT)
    
    async def enrich_ip(self, ip: str) -> ThreatIntelResult:
        """Enrich IP address with multiple TI sources"""
        results = []
        
        # AbuseIPDB
        if ABUSEIPDB_KEY:
            result = await self._query_abuseipdb(ip)
            if result:
                results.append(result)
        
        # GreyNoise
        if GREYNOISE_KEY:
            result = await self._query_greynoise(ip)
            if result:
                results.append(result)
        
        # Aggregate
        if results:
            avg_score = sum(r.reputation_score for r in results) // len(results)
            all_tags = [tag for r in results for tag in r.tags]
            sources = ", ".join(set(r.source for r in results))
            
            return ThreatIntelResult(
                value=ip,
                type="ip",
                reputation_score=avg_score,
                tags=list(set(all_tags)),
                source=sources
            )
        
        return ThreatIntelResult(value=ip, type="ip", reputation_score=0)
    
    async def _query_abuseipdb(self, ip: str) -> Optional[ThreatIntelResult]:
        """Query AbuseIPDB for IP reputation"""
        if not ABUSEIPDB_KEY:
            return None
        
        try:
            headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            
            async with self.session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    info = data.get("data", {})
                    return ThreatIntelResult(
                        value=ip,
                        type="ip",
                        reputation_score=min(info.get("abuseConfidenceScore", 0), 100),
                        malicious_count=info.get("totalReports", 0),
                        tags=[info.get("usageType", "")] if info.get("usageType") else [],
                        source="AbuseIPDB"
                    )
        except Exception as e:
            print(f"AbuseIPDB error for {ip}: {e}")
        
        return None
    
    async def _query_greynoise(self, ip: str) -> Optional[ThreatIntelResult]:
        """Query GreyNoise for IP classification"""
        if not GREYNOISE_KEY:
            return None
        
        try:
            headers = {"key": GREYNOISE_KEY}
            
            async with self.session.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers=headers
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    info = data.get("data", {})
                    return ThreatIntelResult(
                        value=ip,
                        type="ip",
                        reputation_score=50 if info.get("classification") == "malicious" else 0,
                        tags=info.get("tags", []),
                        source="GreyNoise"
                    )
        except Exception as e:
            print(f"GreyNoise error for {ip}: {e}")
        
        return None
    
    async def enrich_hash(self, sha256: str) -> ThreatIntelResult:
        """Enrich file hash with VirusTotal"""
        if not VT_KEY:
            return ThreatIntelResult(value=sha256, type="hash")
        
        try:
            headers = {"x-apikey": VT_KEY}
            
            async with self.session.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers=headers
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    return ThreatIntelResult(
                        value=sha256,
                        type="hash",
                        reputation_score=min(malicious * 10, 100),
                        malicious_count=malicious,
                        source="VirusTotal"
                    )
        except Exception as e:
            print(f"VirusTotal error for {sha256}: {e}")
        
        return ThreatIntelResult(value=sha256, type="hash")
    
    async def close(self):
        """Close aiohttp session"""
        await self.session.close()