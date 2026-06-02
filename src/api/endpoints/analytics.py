"""Analytics API endpoints - PostgreSQL powered attack timeline"""
from fastapi import APIRouter, Depends
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel

from sqlalchemy.orm import Session
from src.core.database import get_db, SessionDB, CommandDB, AttackDB, AttackerDB

router = APIRouter(prefix="/analytics", tags=["analytics"])


class AttackEvent(BaseModel):
    timestamp: datetime
    session_id: str
    attacker_ip: str
    event_type: str  # login, command, download
    command: Optional[str] = None
    payload: Optional[str] = None
    attack_type: Optional[str] = None
    severity: Optional[int] = None
    iocs: Optional[dict] = None


class SessionTimeline(BaseModel):
    session_id: str
    attacker_ip: str
    protocol: str
    start_time: datetime
    end_time: Optional[datetime] = None
    events: List[dict]
    commands: List[str]
    iocs_detected: List[str]
    threat_class: str


@router.get("/session-timeline/{session_id}", response_model=SessionTimeline)
def get_session_timeline(session_id: str, db: Session = Depends(get_db)):
    """Get complete chronological timeline of a session attack"""
    # Get session
    db_session = db.query(SessionDB).filter(SessionDB.id == session_id).first()
    if not db_session:
        return SessionTimeline(
            session_id=session_id, attacker_ip="unknown", protocol="SSH",
            start_time=datetime.utcnow(), events=[], commands=[], iocs_detected=[], threat_class="UNKNOWN"
        )
    
    # Get all commands in order
    commands = db.query(CommandDB).filter(CommandDB.session_id == session_id).order_by(CommandDB.timestamp).all()
    
    # Get attacker info
    attacker = db.query(AttackerDB).filter(AttackerDB.ip == db_session.attacker_ip).first()
    
    # Build timeline
    events = []
    ioc_values = []
    
    for cmd in commands:
        events.append({
            "timestamp": cmd.timestamp.isoformat() if cmd.timestamp else None,
            "type": "command",
            "content": cmd.command[:100],
            "flagged": cmd.flagged
        })
    
    # Calculate threat class from commands
    threat_class = "UNKNOWN"
    cmd_str = " ".join(c.command.lower() for c in commands)
    if any(t in cmd_str for t in ["nmap", "masscan", "nikto", "sqlmap"]):
        threat_class = "AUTOMATED_SCANNER"
    elif any(t in cmd_str for t in ["wget", "curl"]) and "http" in cmd_str:
        threat_class = "MALWARE_DOWNLOAD"
    
    return SessionTimeline(
        session_id=db_session.id,
        attacker_ip=db_session.attacker_ip,
        protocol=db_session.protocol or "SSH",
        start_time=db_session.start_time,
        end_time=db_session.end_time,
        events=events,
        commands=[c.command for c in commands],
        iocs_detected=ioc_values,
        threat_class=threat_class
    )


@router.get("/attack-feed", response_model=List[AttackEvent])
def get_attack_feed(limit: int = 100, db: Session = Depends(get_db)):
    """Get all attack events chronologically"""
    # Get commands with session info
    cmd_data = db.query(CommandDB, SessionDB).join(SessionDB).order_by(CommandDB.timestamp.desc()).limit(limit).all()
    
    events = []
    for cmd, session in cmd_data:
        events.append(AttackEvent(
            timestamp=cmd.timestamp or datetime.utcnow(),
            session_id=cmd.session_id,
            attacker_ip=session.attacker_ip,
            event_type="command",
            command=cmd.command
        ))
    
    return events