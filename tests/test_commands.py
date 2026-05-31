"""Tests for commands API endpoints"""
import pytest
from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_list_commands():
    response = client.get("/commands")
    assert response.status_code == 200

def test_create_command():
    response = client.post("/commands", json={
        "session_id": 1,
        "command": "ls -la"
    })
    assert response.status_code == 201
    data = response.json()
    assert data["session_id"] == 1
    assert data["command"] == "ls -la"

def test_command_flagged_detection():
    response = client.post("/commands", json={
        "session_id": 1,
        "command": "cat /etc/passwd"
    })
    assert response.status_code == 201
    assert response.json()["flagged"] == True

def test_get_commands_by_session():
    response = client.get("/commands/session/1")
    assert response.status_code == 200
    assert all(c["session_id"] == 1 for c in response.json())