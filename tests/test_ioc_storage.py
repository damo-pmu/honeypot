"""Tests for IOC Storage in DB feature (5.2)"""
import pytest
from datetime import datetime
from src.core.entities.models import IOCIndicator
from src.analytics.ioc_scanner import scan_for_iocs, IOC, extract_hashes, extract_ips, extract_urls
from src.infrastructure.database.queries import (
    create_ioc, get_ioc_by_value, increment_ioc_hit,
    get_top_iocs, get_iocs_by_type
)


class TestIOCScanning:
    """Test IOC extraction functions"""
    
    def test_extract_hashes_sha256(self):
        text = "Here is a hash: a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"
        results = extract_hashes(text)
        assert len(results) == 1
        assert results[0].ioc_type == "hash"
        assert results[0].value == "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"
    
    def test_extract_hashes_md5(self):
        text = "MD5 hash: 5d41402abc4b2a76b9719d911017c592"
        results = extract_hashes(text)
        assert len(results) == 1
        assert results[0].ioc_type == "hash"
    
    def test_extract_hashes_sha1(self):
        text = "SHA1: 2aae6c35c94fcfb415dbe9556294a28acb845bdc"
        results = extract_hashes(text)
        assert len(results) == 1
    
    def test_extract_multiple_hashes(self):
        text = "Hashes: 5d41402abc4b2a76b9719d911017c592 and a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"
        results = extract_hashes(text)
        assert len(results) == 2
    
    def test_extract_ips(self):
        text = "Connecting from 192.168.1.1 and 10.0.0.1 to 8.8.8.8"
        results = extract_ips(text)
        assert len(results) == 3
        values = [r.value for r in results]
        assert "192.168.1.1" in values
        assert "10.0.0.1" in values
        assert "8.8.8.8" in values
    
    def test_extract_urls(self):
        text = "Download from http://malware.example.com/payload.exe and https://evil.org/shell.php"
        results = extract_urls(text)
        assert len(results) == 2
        values = [r.value for r in results]
        assert "http://malware.example.com/payload.exe" in values
        assert "https://evil.org/shell.php" in values
    
    def test_scan_for_iocs_integration(self):
        text = """
        Malware download: http://evil.com/malware.exe
        SHA256: abc123def456789012345678901234567890123456789012345678901234
        C2 server: 1.2.3.4
        """
        results = scan_for_iocs(text)
        assert "hashes" in results
        assert "ips" in results
        assert "urls" in results
        assert results["total"] == 3


class TestIOCIndicatorModel:
    """Test IOCIndicator entity"""
    
    def test_ioc_indicator_creation(self):
        ioc = IOCIndicator(
            ioc_type="hash",
            value="abc123def456",
            confidence=0.95,
            source="manual"
        )
        assert ioc.ioc_type == "hash"
        assert ioc.value == "abc123def456"
        assert ioc.confidence == 0.95
        assert ioc.hit_count == 1
    
    def test_ioc_indicator_with_relationships(self):
        ioc = IOCIndicator(
            ioc_type="ip",
            value="192.168.1.100",
            related_attacker_ip="10.0.0.50",
            related_session_id="sess_123"
        )
        assert ioc.related_attacker_ip == "10.0.0.50"
        assert ioc.related_session_id == "sess_123"
    
    def test_ioc_indicator_defaults(self):
        ioc = IOCIndicator(
            ioc_type="domain",
            value="bad-domain.com"
        )
        assert ioc.confidence == 1.0
        assert ioc.source == "scan"
        assert ioc.hit_count == 1


class TestIOCDatabaseQueries:
    """Test database query generation for IOC operations"""
    
    def test_create_ioc_query(self):
        ioc_data = {
            "ioc_type": "hash",
            "value": "abc123",
            "confidence": 0.85,
            "source": "scan"
        }
        result = create_ioc(ioc_data)
        assert "INSERT" in result["operation"]
        assert "abc123" in result["query"]
    
    def test_get_ioc_by_value_query(self):
        result = get_ioc_by_value("abc123")
        assert "SELECT" in result["operation"]
        assert "abc123" in result["query"]
    
    def test_increment_ioc_hit_query(self):
        result = increment_ioc_hit(123)
        assert "UPDATE" in result["operation"]
        assert "hit_count + 1" in result["query"]
    
    def test_get_top_iocs_query(self):
        results = get_top_iocs(10)
        assert len(results) > 0
        assert "ORDER BY hit_count DESC" in results[0]["query"]
    
    def test_get_iocs_by_type_query(self):
        results = get_iocs_by_type("ip", 25)
        assert len(results) > 0
        assert "ioc_type = 'ip'" in results[0]["query"]


class TestIOCRelationships:
    """Test IOC relationships with attackers and sessions"""
    
    def test_ioc_linked_to_attacker(self):
        """IOC can be linked to an attacker IP"""
        ioc = IOCIndicator(
            ioc_type="ip",
            value="203.0.113.50",
            related_attacker_ip="203.0.113.50",
            confidence=0.99
        )
        assert ioc.related_attacker_ip == "203.0.113.50"
    
    def test_ioc_linked_to_session(self):
        """IOC can be linked to a session ID"""
        ioc = IOCIndicator(
            ioc_type="url",
            value="http://malware.example.com/payload",
            related_session_id="sess_abc123"
        )
        assert ioc.related_session_id == "sess_abc123"