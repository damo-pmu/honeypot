"""Statistics service - aggregates data from repository, no DB access directly"""
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from src.repositories.statistics_repository import StatisticsRepository
from src.repositories.attack_repository import AttackRepository
from src.repositories.session_repository import SessionRepository


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
        """Get recent events for live feed"""
        attacks = self.attack_repo.get_recent(limit=limit)
        # Could also merge commands if needed
        return attacks


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