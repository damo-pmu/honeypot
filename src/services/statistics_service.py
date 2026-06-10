"""Statistics service - aggregates data from repository, no DB access directly"""
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc

from src.repositories.statistics_repository import StatisticsRepository
from src.repositories.attack_repository import AttackRepository
from src.repositories.session_repository import SessionRepository
from src.core.database import AttackDB


class StatisticsService:
    """
    Business logic for statistics - orchestrates repository calls.
    
    All statistics come from PostgreSQL via repositories.
    No in-memory counters or caches.
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.stats_repo = StatisticsRepository(db)
        self.session_repo = SessionRepository(db)
        self.attack_repo = AttackRepository(db)
    
    def get_dashboard_stats(self) -> Dict[str, Any]:
        """
        Aggregate all dashboard statistics.
        Single source of truth: PostgreSQL.
        """
        return self.stats_repo.get_dashboard_stats()
    
    def get_geoip_markers(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get geoip markers for map visualization"""
        return self.stats_repo.get_geoip_markers(limit)
    
    def get_live_feed(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent attacks for live feed with geoip data"""
        from src.core.database import AttackDB, AttackerDB
        attacks = self.db.query(AttackDB).order_by(
            desc(AttackDB.timestamp)
        ).limit(limit).all()
        
        # Build IP -> attacker lookup
        ips = list(set(a.attacker_ip for a in attacks))
        attackers = {a.ip: a for a in self.db.query(AttackerDB).filter(AttackerDB.ip.in_(ips)).all()}
        
        def get_geoip(ip_addr: str):
            attacker = attackers.get(ip_addr)
            return attacker.geoip if attacker else None
        
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
                    "payload": a.payload[:200] if a.payload else None,
                    "session_id": a.session_id,
                    "geoip": get_geoip(a.attacker_ip)
                }
            }
            for a in attacks
        ]


class DashboardService:
    """
    High-level dashboard orchestration service.
    Combines statistics and session data.
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.stats_service = StatisticsService(db)
        self.session_repo = SessionRepository(db)
    
    def get_full_dashboard_state(self) -> Dict[str, Any]:
        """Get complete dashboard state for initial page load"""
        return {
            "stats": self.stats_service.get_dashboard_stats(),
            "live_feed": self.stats_service.get_live_feed(limit=50),
            "geoip_markers": self.stats_service.get_geoip_markers(limit=100),
            "active_sessions": self.session_repo.count_active()
        }