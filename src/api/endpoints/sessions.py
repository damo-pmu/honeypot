"""Sessions API endpoints - FastAPI with PostgreSQL"""
from fastapi import APIRouter, HTTPException, Depends
from typing import List
from pydantic import BaseModel
from datetime import datetime

from sqlalchemy.orm import Session
from src.core.database import get_db, SessionDB, AttackerDB

router = APIRouter(prefix="/sessions", tags=["sessions"])


class SessionBase(BaseModel):
    attacker_ip: str
    protocol: str
    interaction_count: int = 0


class SessionCreate(SessionBase):
    pass


class Session(SessionBase):
    id: str
    start_time: datetime
    end_time: datetime | None = None
    duration_seconds: int | None = None


@router.get("/", response_model=List[Session])
def list_sessions(db: Session = Depends(get_db)):
    """List all sessions"""
    sessions = db.query(SessionDB).order_by(SessionDB.start_time.desc()).limit(100).all()
    return [
        Session(
            id=s.id,
            attacker_ip=s.attacker_ip,
            protocol=s.protocol,
            start_time=s.start_time,
            end_time=s.end_time,
            interaction_count=s.interaction_count,
            duration_seconds=s.duration_seconds
        )
        for s in sessions
    ]


@router.post("/", response_model=Session, status_code=201)
def create_session(session: SessionCreate, db: Session = Depends(get_db)):
    """Create session entry"""
    # Ensure attacker exists
    db_attacker = db.query(AttackerDB).filter(AttackerDB.ip == session.attacker_ip).first()
    if not db_attacker:
        db_attacker = AttackerDB(ip=session.attacker_ip)
        db.add(db_attacker)
        db.commit()
    
    db_session = SessionDB(
        id=session.id,
        attacker_ip=session.attacker_ip,
        protocol=session.protocol,
        start_time=datetime.utcnow(),
        interaction_count=session.interaction_count
    )
    db.add(db_session)
    db.commit()
    db.refresh(db_session)
    
    return Session(
        id=db_session.id,
        attacker_ip=db_session.attacker_ip,
        protocol=db_session.protocol,
        start_time=db_session.start_time,
        end_time=db_session.end_time,
        interaction_count=db_session.interaction_count,
        duration_seconds=db_session.duration_seconds
    )


@router.get("/{session_id}", response_model=Session)
def get_session(session_id: str, db: Session = Depends(get_db)):
    """Get session by ID"""
    db_session = db.query(SessionDB).filter(SessionDB.id == session_id).first()
    if not db_session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return Session(
        id=db_session.id,
        attacker_ip=db_session.attacker_ip,
        protocol=db_session.protocol,
        start_time=db_session.start_time,
        end_time=db_session.end_time,
        interaction_count=db_session.interaction_count,
        duration_seconds=db_session.duration_seconds
    )