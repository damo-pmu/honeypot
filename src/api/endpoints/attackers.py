"""Attackers API endpoints - FastAPI with PostgreSQL"""
from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional
from pydantic import BaseModel
from enum import Enum
from datetime import datetime, timezone

from sqlalchemy.orm import Session
from src.core.database import get_db, AttackerDB, AttackDB, SessionDB

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
    geoip: Optional[dict] = None


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
    """Create attacker entry - accepts geoip for enrichment"""
    db_attacker = db.query(AttackerDB).filter(AttackerDB.ip == attacker.ip).first()
    
    if db_attacker:
        db_attacker.last_seen = datetime.now(timezone.utc)
        db_attacker.threat_score = max(db_attacker.threat_score, attacker.threat_score)
        if attacker.geoip:
            db_attacker.geoip = attacker.geoip
            db_attacker.country = attacker.geoip.get("country")
        db.commit()
        db.refresh(db_attacker)
    else:
        db_attacker = AttackerDB(
            ip=attacker.ip,
            first_seen=attacker.first_seen or datetime.now(timezone.utc),
            threat_score=attacker.threat_score,
            classification=attacker.classification.value,
            geoip=attacker.geoip if attacker.geoip else None,
            country=attacker.geoip.get("country") if attacker.geoip else None
        )
        db.add(db_attacker)
        db.commit()
        db.refresh(db_attacker)
    
    attackers = db.query(AttackerDB).all()
    attacker_id = next((i+1 for i, a in enumerate(attackers) if a.ip == db_attacker.ip), 1)
    
    return Attacker(
        id=attacker_id,
        ip=db_attacker.ip,
        first_seen=db_attacker.first_seen,
        threat_score=db_attacker.threat_score,
        classification=ThreatClass(db_attacker.classification)
    )


@router.get("/{ip}/geolocation", response_model=dict)
def get_attacker_geolocation(ip: str, db: Session = Depends(get_db)):
    """Get attacker geolocation for map visualization - PUBLIC endpoint"""
    attacker = db.query(AttackerDB).filter(AttackerDB.ip == ip).first()
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")
    
    attacks = db.query(AttackDB).filter(
        AttackDB.attacker_ip == ip
    ).order_by(AttackDB.timestamp.desc()).limit(20).all()
    
    sessions = db.query(SessionDB).filter(
        SessionDB.attacker_ip == ip
    ).order_by(SessionDB.start_time.desc()).limit(10).all()
    
    return {
        "ip": ip,
        "geoip": attacker.geoip,
        "country": attacker.country,
        "threat_score": attacker.threat_score,
        "attacks_count": len(attacks),
        "sessions_count": len(sessions),
        "sessions": [
            {
                "id": s.id,
                "start_time": s.start_time.isoformat() if s.start_time else None,
                "end_time": s.end_time.isoformat() if s.end_time else None,
                "duration_seconds": s.duration_seconds,
                "protocol": s.protocol
            }
            for s in sessions
        ],
        "recent_attacks": [
            {
                "id": a.id,
                "attack_type": a.attack_type,
                "severity": a.severity,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "payload": a.payload[:200] if a.payload else None
            }
            for a in attacks[:5]
        ]
    }


@router.get("/{ip}/attacks", response_model=dict)
def get_attacker_attacks(ip: str, db: Session = Depends(get_db), limit: int = 20):
    """Get attacks for a specific attacker IP"""
    attacker = db.query(AttackerDB).filter(AttackerDB.ip == ip).first()
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")
    
    attacks = db.query(AttackDB).filter(
        AttackDB.attacker_ip == ip
    ).order_by(AttackDB.timestamp.desc()).limit(limit).all()
    
    return {
        "ip": ip,
        "attacks": [
            {
                "id": a.id,
                "session_id": a.session_id,
                "attack_type": a.attack_type,
                "severity": a.severity,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "payload": a.payload[:200] if a.payload else None
            }
            for a in attacks
        ]
    }


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