"""Dynamic Risk Engine - Calculate risk scores from attack behaviors"""
from typing import Dict, Any, List, Optional
from enum import Enum
from dataclasses import dataclass, field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Risk scores for each behavior (cumulative)
RISK_SCORES = {
    # Initial Access
    "SSH_LOGIN": 10,
    "TELNET_LOGIN": 10,
    "BRUTE_FORCE": 25,
    
    # Execution
    "WGET": 20,
    "CURL": 20,
    "TFTP": 15,
    "SCP": 15,
    
    # Privilege Escalation
    "SUDO": 30,
    "SU": 25,
    "CHMOD_EXECUTABLE": 25,
    "CHMOD_SUID": 35,
    
    # Command & Control
    "NETCAT": 50,
    "REVERSE_SHELL": 100,
    "SOCAT": 45,
    "BACKDOOR": 75,
    
    # Discovery
    "WHOAMI": 5,
    "ID": 5,
    "UNAME": 5,
    "CAT_ETC_PASSWD": 20,
    
    # Collection
    "TAR": 25,
    "ZIP": 20,
    
    # Impact
    "RM_RF": 40,
    "DD_DESTROY": 50,
    "MKFS": 50,
    "SHUTDOWN": 30,
}


class RiskEngine:
    """
    Calculate cumulative risk score based on attacker behaviors.
    
    Each suspicious action adds to the score.
    Thresholds determine severity level.
    """
    
    SEVERITY_THRESHOLDS = {
        Severity.LOW: (0, 30),
        Severity.MEDIUM: (31, 60),
        Severity.HIGH: (61, 100),
        Severity.CRITICAL: (101, float('inf'))
    }
    
    def __init__(self, events: List[Dict[str, Any]]):
        self.events = events
    
    def calculate(self) -> Dict[str, Any]:
        """Calculate total risk score and severity"""
        total_score = 0
        triggers = []
        
        for event in self.events:
            score, trigger = self._score_event(event)
            if score > 0:
                total_score += score
                triggers.append(trigger)
        
        severity = self._get_severity(total_score)
        
        return {
            "score": total_score,
            "severity": severity,
            "triggers": list(dict.fromkeys(triggers)),  # Dedupe preserving order
        }
    
    def _score_event(self, event: Dict[str, Any]) -> tuple:
        """Score a single event, return (score, trigger_name)"""
        event_type = event.get("type", "")
        attack_type = event.get("data", {}).get("attack_type", "")
        payload = event.get("data", {}).get("payload", "") or ""
        command = event.get("data", {}).get("command", "") or ""
        
        # Check attack type scores
        score = RISK_SCORES.get(attack_type, 0)
        if score > 0:
            return (score, attack_type)
        
        # Check command patterns
        payload_lower = payload.lower()
        command_lower = command.lower()
        
        for pattern, pts in RISK_SCORES.items():
            if pattern in payload_lower or pattern.lower() in command_lower:
                return (pts, pattern)
        
        return (0, None)
    
    def _get_severity(self, score: int) -> str:
        """Get severity label from score"""
        for severity, (low, high) in self.SEVERITY_THRESHOLDS.items():
            if low <= score <= high:
                return severity.value
        return Severity.LOW.value