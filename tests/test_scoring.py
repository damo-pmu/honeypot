"""Tests for scoring engine"""
import pytest
from src.scoring.engine import calculate_score, classify_threat, AttackType

def test_brute_force_score():
    score = calculate_score("brute_force")
    assert score == 20

def test_sql_injection_score():
    score = calculate_score("sqli_attempt")
    assert score == 30

def test_unknown_attack_score():
    score = calculate_score("mystery_attack")
    assert score == 0

def test_classify_botnet():
    classification = classify_threat(60)
    assert classification == "BOTNET_NODE"

def test_classify_scanner():
    classification = classify_threat(35)
    assert classification == "AUTOMATED_SCANNER"

def test_classify_default():
    classification = classify_threat(5)
    assert classification == "UNKNOWN"

def test_case_insensitive():
    assert calculate_score("BRUTE_FORCE") == calculate_score("brute_force")