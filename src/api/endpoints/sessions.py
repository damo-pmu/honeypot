"""Sessions API endpoints - FastAPI"""
from fastapi import APIRouter, HTTPException
from typing import List
from pydantic import BaseModel

router = APIRouter(prefix="/sessions", tags=["sessions"])

class SessionBase(BaseModel):
    attacker_ip: str
    protocol: str
    interaction_count: int = 0

class SessionCreate(SessionBase):
    pass

class Session(SessionBase):
    id: int
    start_time: str
    end_time: str | None = None
    duration_seconds: int | None = None

# In-memory store
_fake_sessions: List[Session] = [
    Session(id=1, attacker_ip="192.168.1.1", protocol="ssh", start_time="2026-05-31T10:00:00", interaction_count=42),
]

@router.get("/", response_model=List[Session])
def list_sessions():
    """List all sessions"""
    return _fake_sessions[:100]

@router.post("/", response_model=Session, status_code=201)
def create_session(session: SessionCreate):
    """Create session entry"""
    from datetime import datetime
    new_id = max(s.id for s in _fake_sessions) + 1 if _fake_sessions else 1
    new_session = Session(
        id=new_id,
        start_time=datetime.utcnow().isoformat(),
        **session.model_dump()
    )
    _fake_sessions.append(new_session)
    return new_session

@router.get("/{session_id}", response_model=Session)
def get_session(session_id: int):
    """Get session by ID"""
    for session in _fake_sessions:
        if session.id == session_id:
            return session
    raise HTTPException(status_code=404, detail="Session not found")