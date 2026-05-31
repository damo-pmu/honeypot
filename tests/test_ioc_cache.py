"""Tests for Redis caching layer (Feature 6.2)"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock


class TestIOCCache:
    """Test IOC caching functionality"""
    
    @pytest.mark.asyncio
    async def test_make_key(self):
        """Test cache key generation"""
        from src.infrastructure.enrichment.cache import IOCCache
        
        cache = IOCCache()
        key = cache._make_key("virustotal", "abc123")
        assert key.startswith("ioc:virustotal:")
        assert len(key.split(":")[-1]) == 8  # MD5 hash truncated
    
    @pytest.mark.asyncio
    async def test_cache_set_get(self):
        """Test cache set and get"""
        from src.infrastructure.enrichment.cache import IOCCache
        
        cache = IOCCache()
        cache._client = AsyncMock()
        
        test_data = {"malicious": 5, "source": "virustotal"}
        await cache.set_cached("vt", "hash123", test_data)
        
        # Verify setex called
        assert cache._client.setex.called
    
    @pytest.mark.asyncio
    async def test_cache_get_miss(self):
        """Test cache miss returns None"""
        from src.infrastructure.enrichment.cache import IOCCache
        
        cache = IOCCache()
        cache._client = AsyncMock()
        cache._client.get.return_value = None
        
        result = await cache.get_cached("vt", "unknown")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_cache_connection(self):
        """Test Redis connection setup"""
        from src.infrastructure.enrichment.cache import IOCCache
        
        with patch("src.infrastructure.enrichment.cache.redis") as mock_redis:
            cache = IOCCache()
            await cache.connect()
            assert cache._client is not None


class TestCachedEnrichment:
    """Test enrichment with caching"""
    
    @pytest.mark.asyncio
    async def test_enrich_uses_cache(self):
        """Test that enrichment checks cache first"""
        from src.infrastructure.enrichment.external import enrich_ioc
        from src.infrastructure.enrichment.cache import IOCCache
        
        with patch.object(IOCCache, 'get_all_cached', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"virustotal": {"malicious": 0}}
            
            result = await enrich_ioc("abc123", "hash", use_cache=True)
            assert result.get("cached") == True
    
    @pytest.mark.asyncio
    async def test_enrich_fresh_on_cache_miss(self):
        """Test fresh lookup when cache empty"""
        from src.infrastructure.enrichment.external import enrich_ioc
        
        with patch('src.infrastructure.enrichment.external.VT_API_KEY', ''):
            result = await enrich_ioc("abc123", "hash", use_cache=False)
            assert result.get("cached") == False
            assert "enrichments" in result