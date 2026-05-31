"""Scoring engine - rules-based threat scoring"""
from enum import Enum
from pydantic import BaseModel
from typing import Dict

class AttackType(str, Enum):
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sqli_attempt"
    MALWARE_DOWNLOAD = "malware_download"
    PORT_SCAN = "port_scan"
    RECONNAISSANCE = "reconnaissance"
    AI_AGENT_PATTERN = "ai_agent_pattern"

class ScoringRule(BaseModel):
    attack_type: AttackType
    score: int
    description: str

# Default rules (loaded from config.yaml in prod)
DEFAULT_RULES: Dict[AttackType, int] = {
    AttackType.BRUTE_FORCE: 20,
    AttackType.SQL_INJECTION: 30,
    AttackType.MALWARE_DOWNLOAD: 50,
    AttackType.PORT_SCAN: 15,
    AttackType.RECONNAISSANCE: 10,
    AttackType.AI_AGENT_PATTERN: 25,
}

def calculate_score(attack_type: str) -> int:
    """Calculate threat score from attack type"""
    try:
        atype = AttackType(attack_type.lower())
        return DEFAULT_RULES.get(atype, 5)
    except ValueError:
        return 0

def classify_threat(score: int) -> str:
    """Classify based on score thresholds"""
    if score >= 50:
        return "BOTNET_NODE"
    elif score >= 30:
        return "AUTOMATED_SCANNER"
    elif score >= 15:
        return "SCRIPT_KIDDIE"
    else:
        return "UNKNOWN"