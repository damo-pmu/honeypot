"""Tests for analytics API endpoints"""
from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_analytics_top_attackers():
    response = client.get("/analytics/top-attackers?limit=5")
    assert response.status_code == 200
    assert "query" in response.json()

def test_analytics_flagged():
    response = client.get("/analytics/flagged-commands")
    assert response.status_code == 200
    assert "flagged" in response.json()["query"]

def test_analytics_timeline():
    response = client.get("/analytics/timeline?hours=12")
    assert response.status_code == 200
    assert "12 hours" in response.json()["query"]