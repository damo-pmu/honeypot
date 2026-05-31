"""Attackers API endpoints - FastAPI"""
from fastapi import APIRouter, HTTPException
from typing import List
from pydantic import BaseModel
from enum import Enum

router = APIRouter(prefix="/attackers", tags=["attackers"])

class ThreatClass(str, Enum):
    BOT = "BOT"
    AUTOMATED_SCANNER = "AUTOMATED_SCANNER"
    HUMAN_OPERATOR = "HUMAN_OPERATOR"
    UNKNOWN = "UNKNOWN"

class AttackerBase(BaseModel):
    ip: str
    first_seen: str | None = None
    threat_score: int = 0
    classification: ThreatClass = ThreatClass.UNKNOWN

class AttackerCreate(AttackerBase):
    pass

class Attacker(AttackerBase):
    id: int

# In-memory store (temporary - DB in Phase 2)
_fake_db: List[Attacker] = [
    Attacker(id=1, ip="192.168.1.1", threat_score=85, classification=ThreatClass.BOT),
    Attacker(id=2, ip="10.0.0.1", threat_score=45, classification=ThreatClass.UNKNOWN),
]

@router.get("/", response_model=List[Attacker])
def list_attackers():
    """List all attackers (max 100)"""
    return _fake_db[:100]

@router.post("/", response_model=Attacker, status_code=201)
def create_attacker(attacker: AttackerCreate):
    """Create attacker entry"""
    new_id = max(a.id for a in _fake_db) + 1
    new_attacker = Attacker(id=new_id, **attacker.model_dump())
    _fake_db.append(new_attacker)
    return new_attacker

@router.get("/{attacker_id}", response_model=Attacker)
def get_attacker(attacker_id: int):
    """Get attacker by ID"""
    for attacker in _fake_db:
        if attacker.id == attacker_id:
            return attacker
    raise HTTPException(status_code=404, detail="Attacker not found")