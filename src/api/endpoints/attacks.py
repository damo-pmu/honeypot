"""Attack events logging endpoint - PostgreSQL integration with Prometheus metrics"""
from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime
from typing import Optional
from pydantic import BaseModel

from sqlalchemy.orm import Session
from src.core.database import get_db, AttackDB
from src.infrastructure.observability.metrics import attacks_total, db_queries, attack_severity

router = APIRouter(prefix="/attacks", tags=["attacks"])


class AttackLog(BaseModel):
    session_id: str
    attacker_ip: str
    attack_type: Optional[str] = None
    payload: Optional[str] = None
    ioc_value: Optional[str] = None
    ioc_type: Optional[str] = None
    severity: int = 50
    protocol: str = "ssh"


@router.post("/log", response_model=dict)
def log_attack(attack: AttackLog, db: Session = Depends(get_db)):
    """Log attack event to database - called by worker"""
    db_attack = AttackDB(
        session_id=attack.session_id,
        attacker_ip=attack.attacker_ip,
        attack_type=attack.attack_type,
        payload=attack.payload,
        ioc_value=attack.ioc_value,
        ioc_type=attack.ioc_type,
        severity=attack.severity,
        timestamp=datetime.utcnow()
    )
    db.add(db_attack)
    db.commit()
    db.refresh(db_attack)
    
    # Prometheus metrics
    attacks_total.labels(
        protocol=attack.protocol,
        type=attack.attack_type or "unknown",
        severity=str(attack.severity)
    ).inc()
    
    attack_severity.observe(attack.severity)
    db_queries.labels(operation="INSERT", table="attacks").inc()
    
    return {
        "status": "logged",
        "id": db_attack.id,
        "attack_type": attack.attack_type
    }


@router.get("/session/{session_id}", response_model=list)
def get_attacks_by_session(session_id: str, db: Session = Depends(get_db)):
    """Get all attacks for a session"""
    attacks = db.query(AttackDB).filter(AttackDB.session_id == session_id).order_by(AttackDB.timestamp).all()
    db_queries.labels(operation="SELECT", table="attacks").inc()
    
    return [
        {
            "id": a.id,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "attack_type": a.attack_type,
            "payload": a.payload[:100] if a.payload else None,
            "severity": a.severity
        }
        for a in attacks
    ]


@router.get("/feed", response_model=list)
def get_attack_feed(limit: int = 100, db: Session = Depends(get_db)):
    """Get recent attacks feed for dashboard"""
    attacks = db.query(AttackDB).order_by(AttackDB.timestamp.desc()).limit(limit).all()
    db_queries.labels(operation="SELECT", table="attacks").inc()
    
    return [
        {
            "id": a.id,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "session_id": a.session_id,
            "attacker_ip": a.attacker_ip,
            "attack_type": a.attack_type,
            "severity": a.severity
        }
        for a in attacks
    ]