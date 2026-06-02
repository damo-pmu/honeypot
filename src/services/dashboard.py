"""Dashboard service - Business logic abstraction for metrics and events"""
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from collections import Counter

from ..core.database import (
    AttackDB, SessionDB, CommandDB,
    AttackerDB, get_db
)


class DashboardRepository:
    """Repository pattern for dashboard data access - single source of truth"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_attacks_count(self, hours: int = 24) -> int:
        """Get attack count for period - optimized single query"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return self.db.query(AttackDB).filter(
            AttackDB.timestamp >= cutoff
        ).count()
    
    def get_unique_ips(self, hours: int = 24) -> int:
        """Get unique attacker IPs for period"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return self.db.query(AttackDB.attacker_ip).filter(
            AttackDB.timestamp >= cutoff
        ).distinct().count()
    
    def get_attacks_by_hour(self, hours: int = 24) -> list[dict]:
        """Timeline data for Grafana-style graph"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        results = self.db.query(
            AttackDB.timestamp, 
            AttackDB.protocol,
            AttackDB.attack_type
        ).filter(AttackDB.timestamp >= cutoff).all()
        
        # Group by hour
        counts = Counter()
        for ts, protocol, attack_type in results:
            hour_key = ts.strftime("%Y-%m-%d %H:00")
            counts[(hour_key, protocol, attack_type)] += 1
        
        return [{"time": k[0], "protocol": k[1], "type": k[2], "count": v} 
                for k, v in sorted(counts.items())]
    
    def get_top_attackers(self, limit: int = 10) -> list[dict]:
        """Top attackers by attack count"""
        # Simpler query - join attacks and count
        from sqlalchemy import func
        results = self.db.query(
            AttackDB.attacker_ip,
            AttackerDB.country,
            AttackerDB.threat_level,
            func.count(AttackDB.id).label('attack_count')
        ).join(AttackerDB, AttackDB.attacker_ip == AttackerDB.ip, isouter=True
        ).group_by(AttackDB.attacker_ip, AttackerDB.country, AttackerDB.threat_level
        ).order_by(func.count(AttackDB.id).desc()
        ).limit(limit).all()
        
        return [{"ip": r[0], "country": r[1] or "unknown", 
                 "threat_level": r[2] or "unknown", "count": r[3]} 
                for r in results]


class DashboardService:
    """Service layer - aggregates DB metrics (Prometheus accessed via /metrics endpoint)"""
    
    def __init__(self, db: Optional[Session] = None):
        self._repo = DashboardRepository(db) if db else None
    
    def get_live_stats(self) -> dict:
        """Live dashboard stats from DB (Prometheus metrics separate via /metrics)"""
        # DB stats (detailed)
        db_stats = {
            "attacks_24h": self._repo.get_attacks_count(hours=24) if self._repo else 0,
            "unique_ips_24h": self._repo.get_unique_ips(hours=24) if self._repo else 0,
        }
        
        return {
            "database": db_stats,
            "timestamp": datetime.utcnow().isoformat()
        }