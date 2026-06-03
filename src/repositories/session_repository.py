"""Repository layer for honeypot sessions - single source of truth for PostgreSQL queries"""
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, or_

from src.core.database import SessionDB, AttackDB, CommandDB, AttackerDB


class SessionRepository:
    """Pure data access - no business logic"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create(self, session_id: str, attacker_ip: str, protocol: str) -> SessionDB:
        """Create new session record"""
        session = SessionDB(
            id=session_id,
            attacker_ip=attacker_ip,
            protocol=protocol
        )
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session
    
    def get_by_id(self, session_id: str) -> Optional[SessionDB]:
        """Get session by ID"""
        return self.db.query(SessionDB).filter(SessionDB.id == session_id).first()
    
    def update_end(self, session_id: str) -> Optional[SessionDB]:
        """Update session end time and calculate duration"""
        session = self.get_by_id(session_id)
        if not session:
            return None
        
        if session.start_time:
            session.duration_seconds = int(
                (datetime.utcnow() - session.start_time).total_seconds()
            )
        session.end_time = datetime.utcnow()
        self.db.commit()
        return session
    
    def get_active(self) -> List[SessionDB]:
        """Get all active (not ended) sessions"""
        return self.db.query(SessionDB).filter(
            SessionDB.end_time.is_(None)
        ).all()
    
    def get_list(self, limit: int = 50, offset: int = 0,
                 protocol: Optional[str] = None,
                 ip: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get sessions list with optional filtering"""
        query = self.db.query(SessionDB)
        
        if protocol:
            query = query.filter(SessionDB.protocol == protocol)
        if ip:
            query = query.filter(SessionDB.attacker_ip == ip)
        
        sessions = query.order_by(
            desc(SessionDB.start_time)
        ).limit(limit).offset(offset).all()
        
        return [
            {
                "id": s.id,
                "attacker_ip": s.attacker_ip,
                "protocol": s.protocol,
                "start_time": s.start_time.isoformat() if s.start_time else None,
                "end_time": s.end_time.isoformat() if s.end_time else None,
                "duration_seconds": s.duration_seconds,
                "interaction_count": s.interaction_count
            }
            for s in sessions
        ]
    
    def get_full_detail(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session with all related data for investigation panel"""
        session = self.get_by_id(session_id)
        if not session:
            return None
        
        attacker = self.db.query(AttackerDB).filter(
            AttackerDB.ip == session.attacker_ip
        ).first()
        
        attacks = self.db.query(AttackDB).filter(
            AttackDB.session_id == session_id
        ).order_by(AttackDB.timestamp).all()
        
        commands = self.db.query(CommandDB).filter(
            CommandDB.session_id == session_id
        ).order_by(CommandDB.timestamp).all()
        
        # Build timeline
        timeline = []
        for a in attacks:
            timeline.append({
                "type": "attack",
                "timestamp": a.timestamp.isoformat(),
                "data": {
                    "attack_type": a.attack_type,
                    "protocol": a.protocol,
                    "severity": a.severity,
                    "attacker_ip": a.attacker_ip
                }
            })
        for c in commands:
            timeline.append({
                "type": "command",
                "timestamp": c.timestamp.isoformat(),
                "data": {
                    "command": c.command,
                    "is_flagged": c.flagged,
                    "attacker_ip": c.attacker_ip
                }
            })
        
        timeline.sort(key=lambda x: x["timestamp"])
        
        return {
            "id": session.id,
            "attacker_ip": session.attacker_ip,
            "protocol": session.protocol,
            "start_time": session.start_time.isoformat() if session.start_time else None,
            "end_time": session.end_time.isoformat() if session.end_time else None,
            "duration_seconds": session.duration_seconds,
            "geoip": attacker.geoip if attacker else None,
            "threat_score": attacker.threat_score if attacker else 0,
            "commands": [
                {"command": c.command, "flagged": c.flagged, "timestamp": c.timestamp.isoformat()}
                for c in commands
            ],
            "attacks": [
                {"attack_type": a.attack_type, "severity": a.severity, "payload": a.payload}
                for a in attacks
            ],
            "timeline": timeline
        }
    
    def count_active(self) -> int:
        """Count active sessions"""
        return self.db.query(SessionDB).filter(
            SessionDB.end_time.is_(None)
        ).count()
    
    def count_total(self, hours: int = 24) -> int:
        """Count sessions in period"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return self.db.query(SessionDB).filter(
            SessionDB.start_time >= cutoff
        ).count()
    
    def delete_old(self, days: int = 90) -> int:
        """Delete sessions older than specified days - for retention"""
        cutoff = datetime.utcnow() - timedelta(days=days)
        deleted = self.db.query(SessionDB).filter(
            SessionDB.start_time < cutoff
        ).delete()
        self.db.commit()
        return deleted