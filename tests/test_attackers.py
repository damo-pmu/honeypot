"""Tests for attackers API endpoints"""
import pytest
from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_list_attackers():
    response = client.get("/attackers")
    assert response.status_code == 200
    assert len(response.json()) >= 0

def test_create_attacker():
    response = client.post("/attackers", json={"ip": "test-ip", "threat_score": 50})
    assert response.status_code == 201
    data = response.json()
    assert data["ip"] == "test-ip"
    assert data["threat_score"] == 50

def test_get_attacker_found():
    response = client.get("/attackers/1")
    assert response.status_code == 200

def test_get_attacker_not_found():
    response = client.get("/attackers/9999")
    assert response.status_code == 404