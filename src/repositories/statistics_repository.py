"""Repository layer for statistics - single source of truth aggregating from PostgreSQL"""
from datetime import datetime, timezone, timedelta, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from src.core.database import AttackDB, SessionDB, AttackerDB, CommandDB, IOCDb


class StatisticsRepository:
    """Pure statistical queries - no business logic"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get all dashboard statistics from DB - single source of truth"""
        # Total events (attacks + commands)
        total_events = self.db.query(AttackDB).count()
        total_commands = self.db.query(CommandDB).count()
        
        # Attacks in 24h
        cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
        attacks_24h = self.db.query(AttackDB).filter(
            AttackDB.timestamp >= cutoff_24h
        ).count()
        
        # Unique IPs in 24h
        unique_ips_24h = self.db.query(AttackDB.attacker_ip).filter(
            AttackDB.timestamp >= cutoff_24h
        ).distinct().count()
        
        # Active sessions
        active_sessions = self.db.query(SessionDB).filter(
            SessionDB.end_time.is_(None)
        ).count()
        
        # Unique attackers (total)
        unique_attackers = self.db.query(AttackerDB).count()
        
        # High threat count (threat_score >= 70)
        high_threat_count = self.db.query(AttackerDB).filter(
            AttackerDB.threat_score >= 70
        ).count()
        
        # IOC count
        ioc_count = self.db.query(IOCDb).count()
        
        # Attack type breakdown
        attack_types = self.db.query(
            AttackDB.attack_type,
            func.count(AttackDB.id).label('count')
        ).filter(
            AttackDB.timestamp >= cutoff_24h
        ).group_by(
            AttackDB.attack_type
        ).limit(10).all()
        
        return {
            "total_events": total_events,
            "total_commands": total_commands,
            "attacks_24h": attacks_24h,
            "unique_ips_24h": unique_ips_24h,
            "active_sessions": active_sessions,
            "unique_attackers": unique_attackers,
            "high_threat_count": high_threat_count,
            "ioc_count": ioc_count,
            "attack_type_breakdown": [
                {"type": at.attack_type, "count": at.count}
                for at in attack_types
            ],
            "last_updated": datetime.now(timezone.utc).isoformat()
        }
    
    def get_geoip_markers(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get attacker geoip data for map - already enriched in DB"""
        attackers = self.db.query(
            AttackerDB.ip,
            AttackerDB.country,
            AttackerDB.geoip
        ).filter(
            AttackerDB.geoip.is_not(None)
        ).distinct().limit(limit).all()
        
        markers = []
        for ip, country, geoip in attackers:
            if geoip and isinstance(geoip, dict):
                lat = geoip.get('lat')
                lon = geoip.get('lon')
                if lat and lon:
                    markers.append({
                        "ip": ip,
                        "lat": float(lat),
                        "lon": float(lon),
                        "country": country
                    })
        
        return markers
    
    def get_event_counts_by_type(self, hours: int = 24) -> Dict[str, Any]:
        """Get count of events by type for stats"""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        attack_counts = self.db.query(
            AttackDB.attack_type,
            func.count(AttackDB.id).label('count')
        ).filter(
            AttackDB.timestamp >= cutoff
        ).group_by(
            AttackDB.attack_type
        ).all()
        
        return {
            "attacks": {
                at.attack_type: at.count
                for at in attack_counts
                if at.attack_type
            }
        }