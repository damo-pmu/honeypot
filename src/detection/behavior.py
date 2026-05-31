"""Behavior classification - timing & pattern analysis"""
import statistics
from typing import List

def analyze_timing(latencies: List[float]) -> dict:
    """Analyze interaction timing for bot detection"""
    if not latencies:
        return {"variance": 0, "avg": 0, "is_bot": False}
    
    variance = statistics.variance(latencies) if len(latencies) > 1 else 0
    avg = statistics.mean(latencies)
    
    # Bots have very low timing variance
    is_bot = variance < 0.01 and avg < 2.0
    
    return {
        "variance": round(variance, 4),
        "avg": round(avg, 2),
        "is_bot": is_bot
    }

def detect_patterns(commands: List[str]) -> str:
    """Detect attack patterns in commands"""
    if not commands:
        return "UNKNOWN"
    
    cmd_str = " ".join(commands).lower()
    
    if any(kw in cmd_str for kw in ["select", "union", "drop", "insert"]):
        return "SQL_INJECTION"
    elif any(kw in cmd_str for kw in ["wget", "curl", "chmod", "chmod +x"]):
        return "MALWARE_DOWNLOAD"
    elif len(commands) > 20 and all(len(c) < 10 for c in commands):
        return "PORT_SCAN"
    else:
        return "UNKNOWN"

def classify_behavior(commands: List[str], latencies: List[float]) -> dict:
    """Full behavior classification"""
    timing = analyze_timing(latencies)
    pattern = detect_patterns(commands)
    
    score = 0
    if timing["is_bot"]:
        score += 20
    if pattern != "UNKNOWN":
        score += 15
        
    if score >= 30:
        classification = "AUTOMATED_SCANNER"
    elif score >= 15:
        classification = "BOT"
    else:
        classification = "UNKNOWN"
        
    return {
        "classification": classification,
        "confidence": score,
        "timing": timing,
        "pattern": pattern
    }