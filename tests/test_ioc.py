"""Tests for IOC scanner"""
from fastapi.testclient import TestClient
from app import app
from src.analytics.ioc_scanner import scan_for_iocs

client = TestClient(app)

def test_extract_hashes():
    text = "Found malware d41d8cd98f00b204e9800998ecf8427e and sha256 abc123..."
    result = scan_for_iocs(text)
    assert len(result["hashes"]) >= 1

def test_extract_ips():
    text = "Connection from 192.168.1.1 and 10.0.0.1"
    result = scan_for_iocs(text)
    assert len(result["ips"]) == 2

def test_extract_urls():
    text = "Download from http://evil.com/payload"
    result = scan_for_iocs(text)
    assert len(result["urls"]) == 1

def test_ioc_scan_endpoint():
    response = client.post("/ioc/scan", json={
        "text": "Malware SHA256: abc123def456 and C2 at 10.0.0.1"
    })
    assert response.status_code == 200
    data = response.json()
    assert "hashes" in data
    assert "ips" in data
    assert "urls" in data