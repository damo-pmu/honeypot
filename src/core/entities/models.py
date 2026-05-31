"""Core entities for honeypot framework"""
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class ThreatClass(str, Enum):
    BOT = "BOT"
    AUTOMATED_SCANNER = "AUTOMATED_SCANNER"
    HUMAN_OPERATOR = "HUMAN_OPERATOR"
    SCRIPT_KIDDIE = "SCRIPT_KIDDIE"
    BOTNET_NODE = "BOTNET_NODE"
    POSSIBLE_AI_AGENT = "POSSIBLE_AI_AGENT"
    UNKNOWN = "UNKNOWN"


class Attacker(BaseModel):
    ip: str
    geoip: Optional[dict] = None
    asn: Optional[str] = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    threat_score: int = 0
    classification: ThreatClass = ThreatClass.UNKNOWN
    reputation: Optional[str] = None


class Session(BaseModel):
    id: str
    attacker_ip: str
    protocol: str
    start_time: datetime = Field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    interaction_count: int = 0
    duration_seconds: Optional[int] = None


class Attack(BaseModel):
    session_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    attack_type: str
    payload: Optional[str] = None
    ioc_value: Optional[str] = None
    ioc_type: Optional[str] = None
    severity: int = 0


class IOCIndicator(BaseModel):
    """Persisted IOC indicator in database"""
    ioc_type: str  # hash, ip, domain, url
    value: str
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: Optional[datetime] = None
    confidence: float = 1.0
    source: str = "scan"
    hit_count: int = 1
    related_attacker_ip: Optional[str] = None
    related_session_id: Optional[str] = None