"""Redis caching layer for IOC enrichment results"""
import inspect
import os
import json
import hashlib
from typing import Optional, Dict, Any

try:
    import redis.asyncio as redis
except ImportError:
    redis = None

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_URL = os.getenv("REDIS_URL", f"redis://{REDIS_HOST}:{REDIS_PORT}")
DEFAULT_TTL = 3600  # 1 hour


class IOCCache:
    """Cache layer for threat intelligence lookups"""
    
    def __init__(self, redis_url: str = REDIS_URL):
        self.redis_url = redis_url
        self._client: Optional[redis.Redis] = None
        self._local_cache: Dict[str, str] = {}
        self._use_local_cache = False
    
    async def connect(self):
        """Initialize Redis connection"""
        if self._client or redis is None:
            self._use_local_cache = True
            return

        try:
            self._client = redis.from_url(self.redis_url, decode_responses=True)
            ping_result = self._client.ping()
            if inspect.isawaitable(ping_result):
                await ping_result
        except Exception:
            self._client = None
            self._use_local_cache = True
    
    def _make_key(self, provider: str, value: str) -> str:
        """Create cache key from provider + IOC value"""
        hash_val = hashlib.md5(value.encode()).hexdigest()[:8]
        return f"ioc:{provider}:{hash_val}"
    
    async def get_cached(self, provider: str, value: str) -> Optional[Dict[str, Any]]:
        """Get cached enrichment result"""
        if not self._client and not self._use_local_cache:
            await self.connect()
        
        key = self._make_key(provider, value)
        if self._use_local_cache:
            data = self._local_cache.get(key)
            return json.loads(data) if data else None

        try:
            data = await self._client.get(key)
            return json.loads(data) if data else None
        except Exception:
            self._use_local_cache = True
            return self.get_cached(provider, value)
    
    async def set_cached(self, provider: str, value: str, data: Dict[str, Any], ttl: int = DEFAULT_TTL):
        """Cache enrichment result"""
        if not self._client and not self._use_local_cache:
            await self.connect()
        
        key = self._make_key(provider, value)
        if self._use_local_cache:
            self._local_cache[key] = json.dumps(data)
            return

        try:
            await self._client.setex(key, ttl, json.dumps(data))
        except Exception:
            self._use_local_cache = True
            self._local_cache[key] = json.dumps(data)
    
    async def get_all_cached(self, value: str) -> Dict[str, Optional[Dict]]:
        """Get cached results from all providers"""
        providers = ["virustotal", "abuseipdb", "urlhaus"]
        results = {}
        for provider in providers:
            results[provider] = await self.get_cached(provider, value)
        return results


# Singleton instance
cache = IOCCache()