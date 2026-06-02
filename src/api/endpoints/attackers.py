"""Attackers API endpoints - FastAPI with PostgreSQL"""
from fastapi import APIRouter, HTTPException, Depends
from typing import List
from pydantic import BaseModel
from enum import Enum
from datetime import datetime

from sqlalchemy.orm import Session
from src.core.database import get_db, AttackerDB

router = APIRouter(prefix="/attackers", tags=["attackers"])


class ThreatClass(str, Enum):
    BOT = "BOT"
    AUTOMATED_SCANNER = "AUTOMATED_SCANNER"
    HUMAN_OPERATOR = "HUMAN_OPERATOR"
    UNKNOWN = "UNKNOWN"


class AttackerBase(BaseModel):
    ip: str
    first_seen: datetime | None = None
    threat_score: int = 0
    classification: ThreatClass = ThreatClass.UNKNOWN


class AttackerCreate(AttackerBase):
    pass


class Attacker(AttackerBase):
    id: int


@router.get("/", response_model=List[Attacker])
def list_attackers(db: Session = Depends(get_db)):
    """List all attackers (max 100)"""
    attackers = db.query(AttackerDB).order_by(AttackerDB.first_seen.desc()).limit(100).all()
    return [
        Attacker(
            id=i, ip=a.ip, first_seen=a.first_seen,
            threat_score=a.threat_score, classification=ThreatClass(a.classification)
        )
        for i, a in enumerate(attackers, 1)
    ]


@router.post("/", response_model=Attacker, status_code=201)
def create_attacker(attacker: AttackerCreate, db: Session = Depends(get_db)):
    """Create attacker entry"""
    # Check if exists
    db_attacker = db.query(AttackerDB).filter(AttackerDB.ip == attacker.ip).first()
    
    if db_attacker:
        db_attacker.last_seen = datetime.utcnow()
        db_attacker.threat_score = max(db_attacker.threat_score, attacker.threat_score)
        db.commit()
        db.refresh(db_attacker)
    else:
        db_attacker = AttackerDB(
            ip=attacker.ip,
            first_seen=attacker.first_seen or datetime.utcnow(),
            threat_score=attacker.threat_score,
            classification=attacker.classification.value
        )
        db.add(db_attacker)
        db.commit()
        db.refresh(db_attacker)
    
    # Return with numeric ID for API compatibility
    attackers = db.query(AttackerDB).all()
    attacker_id = next((i+1 for i, a in enumerate(attackers) if a.ip == db_attacker.ip), 1)
    
    return Attacker(
        id=attacker_id,
        ip=db_attacker.ip,
        first_seen=db_attacker.first_seen,
        threat_score=db_attacker.threat_score,
        classification=ThreatClass(db_attacker.classification)
    )


@router.get("/{attacker_id}", response_model=Attacker)
def get_attacker(attacker_id: int, db: Session = Depends(get_db)):
    """Get attacker by ID"""
    attackers = db.query(AttackerDB).all()
    if attacker_id > len(attackers) or attacker_id < 1:
        raise HTTPException(status_code=404, detail="Attacker not found")
    a = attackers[attacker_id - 1]
    return Attacker(
        id=attacker_id, ip=a.ip, first_seen=a.first_seen,
        threat_score=a.threat_score, classification=ThreatClass(a.classification)
    )