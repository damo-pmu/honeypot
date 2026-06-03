"""Attack Replay Service - Reconstruct session chronologically"""
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from sqlalchemy.orm import Session
from src.repositories.attack_repository import AttackRepository
from src.repositories.session_repository import SessionRepository


@dataclass
class ReplayEvent:
    """Single event in session replay"""
    timestamp: datetime
    action: str
    details: Dict[str, Any]
    stage: Optional[str] = None


class ReplayService:
    """
    Replay a honeypot session chronologically.
    
    Fetches all commands/attacks and orders them for investigation.
    """
    
    ACTION_MAP = {
        "login": "SSH Login",
        "command": "Command Execution",
        "download": "Payload Download",
        "upload": "File Upload",
        "disconnect": "Session End"
    }
    
    def __init__(self, session_id: str, db: Session):
        self.session_id = session_id
        self.db = db
        self.attack_repo = AttackRepository(db)
        self.session_repo = SessionRepository(db)
    
    def get_replay(self) -> Dict[str, Any]:
        """Get full session replay"""
        # Get all attacks for this session
        attacks = self.attack_repo.get_by_session(self.session_id)
        
        # Get session info
        session = self.session_repo.get_by_id(self.session_id)
        
        events = []
        start_time = None
        
        for attack in attacks:
            if not start_time:
                start_time = attack.timestamp
            
            events.append(ReplayEvent(
                timestamp=attack.timestamp,
                action=self._classify_action(attack.attack_type, attack.payload),
                details={
                    "attack_type": attack.attack_type,
                    "protocol": attack.protocol,
                    "payload": attack.payload[:500] if attack.payload else None
                }
            ))
        
        # Sort chronologically
        events.sort(key=lambda e: e.timestamp)
        
        return {
            "session_id": self.session_id,
            "start_time": start_time.isoformat() if start_time else None,
            "events": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "action": e.action,
                    "details": e.details
                }
                for e in events
            ],
            "total_events": len(events)
        }
    
    def _classify_action(self, attack_type: str, payload: Optional[str]) -> str:
        """Classify attack into human-readable action"""
        mapping = {
            "SSH_LOGIN": "SSH Login Attempt",
            "TELNET_LOGIN": "Telnet Login Attempt",
            "COMMAND_EXECUTION": "Command Execution",
            "BRUTE_FORCE": "Brute Force Attack",
            "MALWARE_DOWNLOAD": "Malware Download"
        }
        return mapping.get(attack_type, attack_type.replace("_", " ").title())