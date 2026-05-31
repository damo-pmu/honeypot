"""Commands API endpoints - FastAPI"""
from fastapi import APIRouter, HTTPException
from typing import List
from pydantic import BaseModel

router = APIRouter(prefix="/commands", tags=["commands"])

class CommandBase(BaseModel):
    session_id: int
    command: str
    timestamp: str | None = None

class CommandCreate(CommandBase):
    pass

class Command(CommandBase):
    id: int
    flagged: bool = False  # Auto-detection

_fake_commands: List[Command] = [
    Command(id=1, session_id=1, command="whoami", flagged=False),
    Command(id=2, session_id=1, command="cat /etc/passwd", flagged=True),
]

@router.get("/", response_model=List[Command])
def list_commands():
    """List all commands"""
    return _fake_commands[:100]

@router.post("/", response_model=Command, status_code=201)
def create_command(cmd: CommandCreate):
    """Log command execution"""
    from datetime import datetime
    new_id = max(c.id for c in _fake_commands) + 1 if _fake_commands else 1
    flagged = any(kw in cmd.command.lower() for kw in ["passwd", "shadow", "root", "sudo"])
    new_cmd = Command(
        id=new_id,
        timestamp=datetime.utcnow().isoformat(),
        flagged=flagged,
        **cmd.model_dump()
    )
    _fake_commands.append(new_cmd)
    return new_cmd

@router.get("/session/{session_id}", response_model=List[Command])
def get_commands_by_session(session_id: int):
    """Get all commands for a session"""
    return [c for c in _fake_commands if c.session_id == session_id]