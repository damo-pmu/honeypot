"""Tests for sessions API endpoints"""
import pytest
from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_list_sessions():
    response = client.get("/sessions")
    assert response.status_code == 200
    assert len(response.json()) >= 0

def test_create_session():
    response = client.post("/sessions", json={
        "attacker_ip": "10.0.0.1",
        "protocol": "ssh",
        "interaction_count": 5
    })
    assert response.status_code == 201
    data = response.json()
    assert data["attacker_ip"] == "10.0.0.1"
    assert data["protocol"] == "ssh"

def test_get_session_found():
    create_response = client.post("/sessions", json={
        "attacker_ip": "10.0.0.1",
        "protocol": "ssh",
        "interaction_count": 5
    })
    assert create_response.status_code == 201
    session_id = create_response.json()["id"]

    response = client.get(f"/sessions/{session_id}")
    assert response.status_code == 200

def test_get_session_not_found():
    response = client.get("/sessions/9999")
    assert response.status_code == 404

def test_session_with_minimal_data():
    response = client.post("/sessions", json={"attacker_ip": "127.0.0.1", "protocol": "telnet"})
    assert response.status_code == 201
    assert response.json()["interaction_count"] == 0  # Default value