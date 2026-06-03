"""Repository layer for attack events - single source of truth for PostgreSQL queries"""
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, and_

from src.core.database import AttackDB, AttackerDB


class AttackRepository:
    """Pure data access - no business logic"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create(self, session_id: str, attacker_ip: str, protocol: str,
               attack_type: str, payload: Optional[str] = None,
               severity: int = 0, ioc_value: Optional[str] = None,
               ioc_type: Optional[str] = None) -> AttackDB:
        """Create new attack record"""
        attack = AttackDB(
            session_id=session_id,
            attacker_ip=attacker_ip,
            protocol=protocol,
            attack_type=attack_type,
            payload=payload,
            severity=severity,
            ioc_value=ioc_value,
            ioc_type=ioc_type
        )
        self.db.add(attack)
        self.db.commit()
        self.db.refresh(attack)
        return attack
    
    def get_by_id(self, attack_id: int) -> Optional[AttackDB]:
        """Get attack by ID"""
        return self.db.query(AttackDB).filter(AttackDB.id == attack_id).first()
    
    def get_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent attacks for live feed - ordered by timestamp desc"""
        attacks = self.db.query(AttackDB).order_by(
            desc(AttackDB.timestamp)
        ).limit(limit).all()
        
        return [
            {
                "id": a.id,
                "type": "attack",
                "timestamp": a.timestamp.isoformat(),
                "data": {
                    "attack_type": a.attack_type,
                    "protocol": a.protocol,
                    "attacker_ip": a.attacker_ip,
                    "severity": a.severity,
                    "payload": a.payload[:200] if a.payload else None
                }
            }
            for a in attacks
        ]
    
    def count_by_period(self, hours: int = 24) -> int:
        """Count attacks in time period"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return self.db.query(AttackDB).filter(
            AttackDB.timestamp >= cutoff
        ).count()
    
    def get_unique_ips(self, hours: int = 24) -> int:
        """Count unique attacker IPs in period"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return self.db.query(AttackDB.attacker_ip).filter(
            AttackDB.timestamp >= cutoff
        ).distinct().count()
    
    def get_timeline_data(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get attack timeline grouped by hour - for graph visualization"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        results = self.db.query(
            func.date_trunc('hour', AttackDB.timestamp).label('hour'),
            AttackDB.protocol,
            AttackDB.attack_type,
            func.count().label('count')
        ).filter(
            AttackDB.timestamp >= cutoff
        ).group_by(
            func.date_trunc('hour', AttackDB.timestamp),
            AttackDB.protocol,
            AttackDB.attack_type
        ).order_by('hour').all()
        
        return [
            {
                "time": r.hour.strftime("%Y-%m-%d %H:00"),
                "protocol": r.protocol,
                "type": r.attack_type,
                "count": r.count
            }
            for r in results
        ]
    
    def get_top_attackers(self, limit: int = 10, hours: int = 24) -> List[Dict[str, Any]]:
        """Get top attackers by attack count"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        results = self.db.query(
            AttackDB.attacker_ip,
            AttackerDB.country,
            AttackerDB.threat_level,
            AttackerDB.geoip,
            func.count(AttackDB.id).label('attack_count')
        ).join(
            AttackerDB, AttackDB.attacker_ip == AttackerDB.ip, isouter=True
        ).filter(
            AttackDB.timestamp >= cutoff
        ).group_by(
            AttackDB.attacker_ip,
            AttackerDB.country,
            AttackerDB.threat_level,
            AttackerDB.geoip
        ).order_by(
            func.count(AttackDB.id).desc()
        ).limit(limit).all()
        
        return [
            {
                "ip": r.attacker_ip,
                "country": r.country or "unknown",
                "threat_level": r.threat_level or "unknown",
                "geoip": r.geoip,
                "count": r.attack_count
            }
            for r in results
        ]
    
    def delete_old(self, days: int = 90) -> int:
        """Delete attacks older than specified days - for retention"""
        cutoff = datetime.utcnow() - timedelta(days=days)
        deleted = self.db.query(AttackDB).filter(
            AttackDB.timestamp < cutoff
        ).delete()
        self.db.commit()
        return deleted
    
    def get_by_session(self, session_id: str) -> List[Dict[str, Any]]:
        """Get all attacks for a session - for timeline/replay/mitre endpoints"""
        attacks = self.db.query(AttackDB).filter(
            AttackDB.session_id == session_id
        ).order_by(desc(AttackDB.timestamp)).all()
        
        return [
            {
                "id": a.id,
                "timestamp": a.timestamp.isoformat(),
                "attack_type": a.attack_type,
                "protocol": a.protocol,
                "attacker_ip": a.attacker_ip,
                "payload": a.payload,
                "severity": a.severity,
                "ioc_value": a.ioc_value,
                "ioc_type": a.ioc_type
            }
            for a in attacks
        ]