"""Tests for GeoIP enrichment"""
from unittest.mock import patch

from fastapi.testclient import TestClient
from app import app
from src.infrastructure.geoip.enrichment import enrich_ip, detect_vpn_or_tor

client = TestClient(app)


def test_enrich_known_ip():
    with patch("src.infrastructure.geoip.enrichment.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "country": "US",
            "city": "Mountain View",
            "asn": "AS15169 Google LLC",
        }

        result = enrich_ip("8.8.8.8")
        assert result["country"] == "US"
        assert result["city"] == "Mountain View"
        assert result["asn"] == "AS15169"


def test_enrich_private_ip_returns_default():
    result = enrich_ip("192.168.1.1")
    assert result["country"] == "XX"
    assert result["asn"] == "AS0"


def test_enrich_unknown_ip():
    result = enrich_ip("256.256.256.256")
    assert result["country"] == "XX"
    assert result["asn"] == "AS0"


def test_vpn_detection():
    assert detect_vpn_or_tor("AS98765") is True
    assert detect_vpn_or_tor("AS12345") is False


def test_enrichment_api():
    with patch("src.infrastructure.geoip.enrichment.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "country": "US",
            "city": "Mountain View",
            "asn": "AS15169 Google LLC",
        }

        response = client.get("/enrichment/ip?ip=8.8.8.8")
        assert response.status_code == 200
        data = response.json()
        assert data["country"] == "US"
        assert data["asn"] == "AS15169"
