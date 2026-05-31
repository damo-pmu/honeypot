"""Tests for database queries"""
from src.infrastructure.database.queries import get_top_attackers, get_flagged_commands, get_attack_timeline

def test_top_attackers_query():
    result = get_top_attackers(5)
    assert "TOP ATT" in result["query"].upper() or "LIMIT" in result["query"]

def test_flagged_commands_query():
    result = get_flagged_commands()
    assert "flagged = true" in result["query"]

def test_timeline_query():
    result = get_attack_timeline(48)
    assert "INTERVAL '48 hours'" in result["query"]