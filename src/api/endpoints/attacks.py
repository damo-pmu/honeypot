"""Attack events logging endpoint - PostgreSQL integration with Prometheus metrics"""
from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel

from sqlalchemy.orm import Session
from src.core.database import get_db, AttackDB, SessionDB, AttackerDB
from src.infrastructure.observability.metrics import (
    attacks_total, db_queries, attack_severity,
    sessions_total, attackers_total, top_attackers,
    payload_size_bytes
)

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
    """Log attack event to database - called by worker
    Creates session/attacker if they don't exist (idempotent)
    """
    # Ensure attacker exists
    db_attacker = db.query(AttackerDB).filter(AttackerDB.ip == attack.attacker_ip).first()
    if not db_attacker:
        db_attacker = AttackerDB(ip=attack.attacker_ip, threat_score=50)
        db.add(db_attacker)
        db.commit()
        attackers_total.labels(threat_level="new").inc()
        top_attackers.labels(attacker_ip=attack.attacker_ip, country="unknown").inc()
    
    # Ensure session exists
    db_session = db.query(SessionDB).filter(SessionDB.id == attack.session_id).first()
    if not db_session:
        db_session = SessionDB(
            id=attack.session_id,
            attacker_ip=attack.attacker_ip,
            protocol=attack.protocol
        )
        db.add(db_session)
        db.commit()
        sessions_total.labels(protocol=attack.protocol).inc()
    
    # Log attack
    db_attack = AttackDB(
        session_id=attack.session_id,
        attacker_ip=attack.attacker_ip,
        attack_type=attack.attack_type,
        payload=attack.payload,
        ioc_value=attack.ioc_value,
        ioc_type=attack.ioc_type,
        severity=attack.severity,
        timestamp=datetime.now(timezone.utc)
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
    
    # Payload size histogram
    if attack.payload:
        payload_size_bytes.labels(attack_type=attack.attack_type or "unknown").observe(len(attack.payload))
    
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


@router.get("/metrics/summary", response_model=dict)
def get_metrics_summary(db: Session = Depends(get_db)):
    """Get summary metrics for Grafana dashboard - single API call for all counts"""
    total_attacks = db.query(AttackDB).count()
    unique_ips = db.query(AttackerDB).count()
    total_iocs = db.query(AttackerDB).count()
    active_sessions = db.query(SessionDB).filter(SessionDB.end_time.is_(None)).count()
    
    return {
        "total_attacks": total_attacks,
        "unique_attackers": unique_ips,
        "total_iocs": total_iocs,
        "active_sessions": active_sessions
    }