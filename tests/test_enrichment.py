"""Tests for GeoIP enrichment"""
from fastapi.testclient import TestClient
from app import app
from src.infrastructure.geoip.enrichment import enrich_ip, detect_vpn_or_tor

client = TestClient(app)

def test_enrich_known_ip():
    result = enrich_ip("192.168.1.1")
    assert result["country"] == "US"
    assert result["city"] == "San Francisco"

def test_enrich_unknown_ip():
    result = enrich_ip("256.256.256.256")
    assert result["country"] == "XX"

def test_vpn_detection():
    assert detect_vpn_or_tor("AS98765") == True  # Vietnamese - likely VPN
    assert detect_vpn_or_tor("AS12345") == False

def test_enrichment_api():
    response = client.get("/enrichment/ip?ip=10.0.0.1")
    assert response.status_code == 200
    data = response.json()
    assert "country" in data
    assert "asn" in data