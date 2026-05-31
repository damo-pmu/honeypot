"""Tests for behavior API endpoints"""
from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_behavior_classification():
    response = client.post("/behavior/classify", json={
        "commands": ["whoami", "cat /etc/passwd"],
        "latencies": [0.5, 1.0, 0.8]
    })
    assert response.status_code == 200
    data = response.json()
    assert "classification" in data
    assert "confidence" in data

def test_bot_behavior():
    response = client.post("/behavior/classify", json={
        "commands": ["ls", "pwd", "id"] * 30,
        "latencies": [0.1] * 30  # Consistent timing = bot
    })
    assert response.status_code == 200