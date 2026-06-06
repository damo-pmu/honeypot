"""Redis caching layer for IOC enrichment results"""
import os
import json
import hashlib
from typing import Optional, Dict, Any
import redis.asyncio as redis

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_URL = os.getenv("REDIS_URL", f"redis://{REDIS_HOST}:{REDIS_PORT}")
DEFAULT_TTL = 3600  # 1 hour


class IOCCache:
    """Cache layer for threat intelligence lookups"""
    
    def __init__(self, redis_url: str = REDIS_URL):
        self.redis_url = redis_url
        self._client: Optional[redis.Redis] = None
    
    async def connect(self):
        """Initialize Redis connection"""
        if not self._client:
            self._client = redis.from_url(self.redis_url, decode_responses=True)
    
    def _make_key(self, provider: str, value: str) -> str:
        """Create cache key from provider + IOC value"""
        hash_val = hashlib.md5(value.encode()).hexdigest()[:8]
        return f"ioc:{provider}:{hash_val}"
    
    async def get_cached(self, provider: str, value: str) -> Optional[Dict[str, Any]]:
        """Get cached enrichment result"""
        if not self._client:
            await self.connect()
        
        key = self._make_key(provider, value)
        data = await self._client.get(key)
        return json.loads(data) if data else None
    
    async def set_cached(self, provider: str, value: str, data: Dict[str, Any], ttl: int = DEFAULT_TTL):
        """Cache enrichment result"""
        if not self._client:
            await self.connect()
        
        key = self._make_key(provider, value)
        await self._client.setex(key, ttl, json.dumps(data))
    
    async def get_all_cached(self, value: str) -> Dict[str, Optional[Dict]]:
        """Get cached results from all providers"""
        providers = ["virustotal", "abuseipdb", "urlhaus"]
        results = {}
        for provider in providers:
            results[provider] = await self.get_cached(provider, value)
        return results


# Singleton instance
cache = IOCCache()