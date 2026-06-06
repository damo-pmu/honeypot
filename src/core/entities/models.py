"""Core entities for honeypot framework - with explicit relationships

MCD Guidelines:
- All FKs explicit, timestamps on all tables
- Inverse relationships for audit navigation
- Fields indexed: attacker_ip, session_id, timestamp, hit_count
"""
from datetime import datetime
from enum import Enum
from typing import Optional, List
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
    """Attacker entity - PK: ip"""
    ip: str
    geoip: Optional[dict] = None
    asn: Optional[str] = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    threat_score: int = 0
    classification: ThreatClass = ThreatClass.UNKNOWN
    reputation: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    
    # Inverse relation (populated by query)
    sessions: Optional[List[str]] = None


class Session(BaseModel):
    """Session entity - PK: id, FK: attacker_ip -> Attacker.ip"""
    id: str
    attacker_ip: str  # FK to Attacker.ip
    protocol: str
    start_time: datetime = Field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    interaction_count: int = 0
    duration_seconds: Optional[int] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    
    # Inverse relations (populated by query)
    commands: Optional[List[dict]] = None
    attacks: Optional[List[dict]] = None
    iocs: Optional[List[str]] = None


class Command(BaseModel):
    """Command entity - PK: id, FK: session_id -> Session.id"""
    id: int = 0  # SERIAL in DB
    session_id: str  # FK to Session.id
    command: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    flagged: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Attack(BaseModel):
    """Attack entity - PK: id, FK: session_id -> Session.id"""
    id: int = 0  # SERIAL in DB
    session_id: str  # FK to Session.id
    attacker_ip: Optional[str] = None  # Denormalized for fast lookup
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    attack_type: str
    payload: Optional[str] = None
    ioc_value: Optional[str] = None
    ioc_type: Optional[str] = None
    severity: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)


class IOCType(str, Enum):
    HASH = "hash"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"


class IOCIndicator(BaseModel):
    """Persisted IOC indicator - PK: id"""
    id: int = 0  # SERIAL in DB
    ioc_type: IOCType
    value: str
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: Optional[datetime] = None
    confidence: float = 1.0
    source: str = "scan"
    hit_count: int = 1
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    related_attacker_ip: Optional[str] = None
    related_session_id: Optional[str] = None
    
    # Inverse relation - sessions using this IOC
    related_sessions: Optional[List[str]] = None


class IOCSessionLink(BaseModel):
    """Many-to-Many link between IOC and Session"""
    ioc_id: int
    session_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)