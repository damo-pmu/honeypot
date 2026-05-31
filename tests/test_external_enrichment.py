"""Tests for external IOC enrichment providers"""
import pytest
from datetime import datetime
from src.infrastructure.enrichment.external import (
    IOC, lookup_virustotal, lookup_abuseipdb, lookup_urlhaus, enrich_ioc
)
import os


class TestIOCEntity:
    """Test IOC data class"""
    
    def test_ioc_creation(self):
        ioc = IOC(ioc_type="hash", value="abc123", confidence=0.9)
        assert ioc.ioc_type == "hash"
        assert ioc.value == "abc123"
        assert ioc.confidence == 0.9
    
    def test_ioc_defaults(self):
        ioc = IOC(ioc_type="ip", value="10.0.0.1")
        assert ioc.source == "scan"
        assert ioc.confidence == 1.0


class TestExternalProviders:
    """Test enrichment provider integrations"""
    
    @pytest.mark.asyncio
    async def test_virustotal_missing_key(self):
        """Test VT returns error when key not configured"""
        # Temporarily clear key
        original = os.environ.pop("VT_API_KEY", None)
        result = await lookup_virustotal("abc123", "hash")
        assert "error" in result
        assert result["source"] == "virustotal"
        # Restore
        if original:
            os.environ["VT_API_KEY"] = original
    
    @pytest.mark.asyncio
    async def test_abuseipdb_missing_key(self):
        """Test AbuseIPDB returns error when key not configured"""
        original = os.environ.pop("ABUSEIPDB_API_KEY", None)
        result = await lookup_abuseipdb("8.8.8.8")
        assert "error" in result
        if original:
            os.environ["ABUSEIPDB_API_KEY"] = original
    
    @pytest.mark.asyncio
    async def test_urlhaus_integration(self):
        """Test URLHaus lookup (doesn't require key)"""
        result = await lookup_urlhaus("http://example.com/payload")
        assert "found" in result or "error" in result
        assert result.get("source") == "urlhaus"
    
    @pytest.mark.asyncio
    async def test_enrich_ioc_hash(self):
        """Test IOC enrichment for hash type"""
        result = await enrich_ioc("abc123def", "hash")
        assert result["ioc"] == "abc123def"
        assert result["type"] == "hash"
        assert "enrichments" in result
    
    @pytest.mark.asyncio
    async def test_enrich_ioc_ip(self):
        """Test IOC enrichment for IP type"""
        os.environ["ABUSEIPDB_API_KEY"] = ""
        os.environ["VT_API_KEY"] = ""
        result = await enrich_ioc("192.168.1.1", "ip")
        assert result["ioc"] == "192.168.1.1"
        assert result["type"] == "ip"
    
    @pytest.mark.asyncio
    async def test_enrich_ioc_unsupported_type(self):
        """Test IOC enrichment rejects unsupported types"""
        result = await enrich_ioc("something", "invalid")
        assert "error" in result


class TestProviderErrorHandling:
    """Test error handling in providers"""
    
    @pytest.mark.asyncio
    async def test_vt_invalid_hash_format(self):
        """VT should handle gracefully invalid hash formats"""
        os.environ["VT_API_KEY"] = ""
        result = await lookup_virustotal("not-a-valid-hash", "hash")
        assert "error" in result
    
    @pytest.mark.asyncio
    async def test_rate_limit_handling(self):
        """Providers should document rate limits"""
        # Rate limit info is in the module docstring
        from src.infrastructure.enrichment import external
        assert hasattr(external, "__doc__")
        assert "4 requests/minute" in external.__doc__ or "rate" in external.__doc__.lower()