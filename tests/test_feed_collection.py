"""Tests for Threat Intelligence Feed Collection (Feature 9)"""
import pytest
from unittest.mock import AsyncMock, patch
from src.infrastructure.feeds.collector import fetch_urlhaus, fetch_compromised_ips, fetch_all_feeds


class TestFeedCollection:
    """Test feed collection functions"""
    
    @pytest.mark.asyncio
    async def test_fetch_urlhaus_mock(self):
        """Test URLHaus fetch with mock"""
        mock_csv = "id,url,threat,tags\n1,http://evil.com/malware,malware,tag1\n2,http://bad.org/shell,backdoor,tag2"
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get.return_value = AsyncMock(
                status_code=200,
                text=mock_csv
            )
            mock_client.return_value.__aenter__.return_value = mock_instance
            
            results = await fetch_urlhaus()
            assert len(results) == 2
            assert results[0]["ioc_type"] == "url"
            assert "evil.com" in results[0]["value"]
    
    @pytest.mark.asyncio
    async def test_fetch_compromised_ips_mock(self):
        """Test Emerging Threats IP fetch"""
        mock_ips = "1.2.3.4\n5.6.7.8\n# comment\n9.10.11.12"
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get.return_value = AsyncMock(
                status_code=200,
                text=mock_ips
            )
            mock_client.return_value.__aenter__.return_value = mock_instance
            
            results = await fetch_compromised_ips()
            assert len(results) == 3
            assert results[0]["ioc_type"] == "ip"
    
    @pytest.mark.asyncio
    async def test_fetch_all_feeds(self):
        """Test parallel feed fetching"""
        with patch("src.infrastructure.feeds.collector.fetch_urlhaus", new_callable=AsyncMock) as mock_urlhaus, \
             patch("src.infrastructure.feeds.collector.fetch_compromised_ips", new_callable=AsyncMock) as mock_ips:
            
            mock_urlhaus.return_value = [{"ioc_type": "url", "value": "http://test.com"}]
            mock_ips.return_value = [{"ioc_type": "ip", "value": "10.0.0.1"}]
            
            results = await fetch_all_feeds()
            assert "urlhaus" in results
            assert "emerging_threats" in results


class TestFeedStorage:
    """Test feed storage integration"""
    
    def test_store_feeds_count(self):
        """Test IOC storage count"""
        from src.infrastructure.feeds.collector import store_feeds
        
        iocs = [
            {"ioc_type": "ip", "value": "1.2.3.4"},
            {"ioc_type": "url", "value": "http://evil.com"}
        ]
        count = store_feeds(iocs)
        assert count == 2