"""Repository layer for payloads - single source of truth for PostgreSQL queries"""
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session

from src.core.database import PayloadDB


class PayloadRepository:
    """Pure data access for payload analysis records"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create(self, sha256: str, md5: str = None, size: int = 0,
               entropy: float = None, file_type: str = None,
               strings: List[str] = None, suspicious: List[str] = None,
               packed: bool = False, analysis: Dict = None,
               source_session_id: str = None) -> PayloadDB:
        """Create payload record"""
        payload = PayloadDB(
            sha256=sha256,
            md5=md5,
            size=size,
            entropy=entropy,
            file_type=file_type,
            strings=strings,
            suspicious=suspicious,
            packed=packed,
            analysis=analysis,
            source_session_id=source_session_id
        )
        self.db.add(payload)
        self.db.commit()
        self.db.refresh(payload)
        return payload
    
    def get_by_sha256(self, sha256: str) -> Optional[PayloadDB]:
        """Get payload by SHA256 hash"""
        return self.db.query(PayloadDB).filter(PayloadDB.sha256 == sha256).first()
    
    def get_recent(self, limit: int = 50, packed_only: bool = False) -> List[PayloadDB]:
        """Get recent payloads"""
        query = self.db.query(PayloadDB)
        if packed_only:
            query = query.filter(PayloadDB.packed == True)
        return query.order_by(PayloadDB.first_seen.desc()).limit(limit).all()
    
    def delete_old(self, days: int = 30) -> int:
        """Delete payloads older than N days - cleanup job"""
        cutoff = datetime.utcnow() - timedelta(days=days)
        deleted = self.db.query(PayloadDB).filter(
            PayloadDB.first_seen < cutoff
        ).delete()
        self.db.commit()
        return deleted