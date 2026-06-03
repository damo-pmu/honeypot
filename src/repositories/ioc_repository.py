"""Repository layer for IOCs - single source of truth for PostgreSQL queries"""
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session

from src.core.database import IOCDb


class IOCRepository:
    """Pure data access for IOC indicators"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create_or_update(self, ioc_type: str, value: str, 
                         confidence: float = 1.0, source: str = "scan",
                         related_session_id: str = None) -> IOCDb:
        """Create IOC or update hit count if exists"""
        existing = self.db.query(IOCDb).filter(
            IOCDb.ioc_type == ioc_type,
            IOCDb.value == value
        ).first()
        
        if existing:
            existing.hit_count += 1
            existing.last_seen = datetime.utcnow()
            if related_session_id:
                # Link to session
                from src.core.database import IOCSessionLink
                link = IOCSessionLink(ioc_id=existing.id, session_id=related_session_id)
                self.db.add(link)
            self.db.commit()
            self.db.refresh(existing)
            return existing
        
        db_ioc = IOCDb(
            ioc_type=ioc_type,
            value=value,
            confidence=confidence,
            source=source,
            hit_count=1
        )
        self.db.add(db_ioc)
        self.db.commit()
        self.db.refresh(db_ioc)
        return db_ioc
    
    def get_by_type(self, ioc_type: str, limit: int = 100) -> List[IOCDb]:
        """Get IOCs by type"""
        return self.db.query(IOCDb).filter(
            IOCDb.ioc_type == ioc_type
        ).order_by(IOCDb.hit_count.desc()).limit(limit).all()
    
    def get_top(self, limit: int = 50) -> List[IOCDb]:
        """Get top IOCs by hit count"""
        return self.db.query(IOCDb).order_by(
            IOCDb.hit_count.desc()
        ).limit(limit).all()