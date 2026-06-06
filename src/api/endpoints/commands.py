"""Commands API endpoints - FastAPI with PostgreSQL"""
from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime, timezone

from sqlalchemy.orm import Session
from src.core.database import get_db, CommandDB, SessionDB, AttackerDB
from src.infrastructure.observability.metrics import db_queries, commands_logged

router = APIRouter(prefix="/commands", tags=["commands"])


class CommandBase(BaseModel):
    session_id: int | str
    attacker_ip: Optional[str] = "unknown"
    command: str
    timestamp: datetime | None = None


class CommandCreate(CommandBase):
    pass


class Command(CommandBase):
    id: int
    flagged: bool = False
    
    class Config:
        # Allow attacker_ip to be None/default to avoid overriding in response
        from_attributes = True


@router.get("/", response_model=List[Command])
def list_commands(db: Session = Depends(get_db)):
    """List all commands"""
    cmds = db.query(CommandDB).order_by(CommandDB.timestamp.desc()).limit(100).all()
    return [
        Command(
            id=c.id,
            session_id=int(c.session_id) if c.session_id.isdigit() else c.session_id,
            command=c.command,
            timestamp=c.timestamp,
            flagged=c.flagged
        )
        for c in cmds
    ]


@router.post("/", response_model=Command, status_code=201)
def create_command(cmd: CommandCreate, db: Session = Depends(get_db)):
    """Log command execution"""
    attacker_ip = cmd.attacker_ip or "unknown"
    raw_session_id = cmd.session_id
    db_session_id = str(raw_session_id)

    # Ensure attacker exists (idempotent FK handling)
    db_attacker = db.query(AttackerDB).filter(AttackerDB.ip == attacker_ip).first()
    if not db_attacker:
        db_attacker = AttackerDB(ip=attacker_ip, threat_score=25)
        db.add(db_attacker)
        db.commit()
    
    # Ensure session exists (idempotent FK handling)
    db_session = db.query(SessionDB).filter(SessionDB.id == db_session_id).first()
    if not db_session:
        db_session = SessionDB(id=db_session_id, attacker_ip=attacker_ip, protocol="unknown")
        db.add(db_session)
        db.commit()
    
    flagged = any(kw in cmd.command.lower() for kw in ["passwd", "shadow", "root", "sudo"])
    
    db_cmd = CommandDB(
        session_id=db_session_id,
        command=cmd.command,
        timestamp=cmd.timestamp or datetime.now(timezone.utc),
        flagged=flagged
    )
    db.add(db_cmd)
    db.commit()
    db.refresh(db_cmd)
    
    commands_logged.labels(flagged=str(flagged)).inc()
    db_queries.labels(operation="INSERT", table="commands").inc()
    
    response_session_id = raw_session_id
    if isinstance(raw_session_id, str) and raw_session_id.isdigit():
        try:
            response_session_id = int(raw_session_id)
        except ValueError:
            response_session_id = raw_session_id

    return Command(
        id=db_cmd.id,
        session_id=response_session_id,
        attacker_ip=db_session.attacker_ip,
        command=db_cmd.command,
        timestamp=db_cmd.timestamp,
        flagged=db_cmd.flagged
    )


@router.get("/session/{session_id}", response_model=List[Command])
def get_commands_by_session(session_id: str, db: Session = Depends(get_db)):
    """Get all commands for a session"""
    cmds = db.query(CommandDB).filter(CommandDB.session_id == session_id).all()
    return [
        Command(
            id=c.id,
            session_id=int(c.session_id) if isinstance(c.session_id, str) and c.session_id.isdigit() else c.session_id,
            command=c.command,
            timestamp=c.timestamp,
            flagged=c.flagged
        )
        for c in cmds
    ]