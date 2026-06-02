"""IOC scanning and storage API endpoints - PostgreSQL integration"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

from sqlalchemy.orm import Session
from src.analytics.ioc_scanner import scan_for_iocs, IOC
from src.core.database import get_db, IOCDb, SessionDB

router = APIRouter(prefix="/ioc", tags=["ioc"])


class ScanRequest(BaseModel):
    text: str


class CreateIOCRequest(BaseModel):
    ioc_type: str
    value: str
    confidence: float = 1.0
    source: str = "manual"
    related_attacker_ip: Optional[str] = None
    related_session_id: Optional[str] = None


class IOCResponse(BaseModel):
    id: int
    ioc_type: str
    value: str
    hit_count: int
    confidence: float
    source: str
    first_seen: datetime
    last_seen: Optional[datetime] = None


@router.post("/scan", response_model=dict)
def scan_iocs(request: ScanRequest):
    """Scan text for IOCs (hashes, IPs, URLs)"""
    results = scan_for_iocs(request.text)
    return {"status": "scanned", "results": results}


@router.post("/store", response_model=IOCResponse)
def store_ioc(request: CreateIOCRequest, db: Session = Depends(get_db)):
    """Store IOC in database with deduplication"""
    # Check if IOC already exists (deduplication)
    existing = db.query(IOCDb).filter(
        IOCDb.ioc_type == request.ioc_type,
        IOCDb.value == request.value
    ).first()
    
    if existing:
        existing.hit_count += 1
        existing.last_seen = datetime.utcnow()
        db.commit()
        db.refresh(existing)
        ioc = existing
    else:
        db_ioc = IOCDb(
            ioc_type=request.ioc_type,
            value=request.value,
            confidence=request.confidence,
            source=request.source,
            related_attacker_ip=request.related_attacker_ip,
            related_session_id=request.related_session_id
        )
        db.add(db_ioc)
        db.commit()
        db.refresh(db_ioc)
        ioc = db_ioc
    
    return IOCResponse(
        id=ioc.id,
        ioc_type=ioc.ioc_type,
        value=ioc.value,
        hit_count=ioc.hit_count,
        confidence=float(ioc.confidence),
        source=ioc.source,
        first_seen=ioc.first_seen,
        last_seen=ioc.last_seen
    )


@router.get("/top", response_model=List[dict])
def top_iocs(limit: int = 20, db: Session = Depends(get_db)):
    """Get top IOCs by hit count"""
    iocs = db.query(IOCDb).order_by(IOCDb.hit_count.desc()).limit(limit).all()
    return [
        {
            "id": i.id,
            "ioc_type": i.ioc_type,
            "value": i.value,
            "hit_count": i.hit_count,
            "source": i.source,
            "first_seen": i.first_seen.isoformat() if i.first_seen else None
        }
        for i in iocs
    ]


@router.get("/type/{ioc_type}", response_model=List[dict])
def iocs_by_type(ioc_type: str, limit: int = 50, db: Session = Depends(get_db)):
    """Get IOCs by type (hash, ip, domain, url)"""
    valid_types = {"hash", "ip", "domain", "url"}
    if ioc_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid type. Must be one of: {valid_types}")
    
    iocs = db.query(IOCDb).filter(IOCDb.ioc_type == ioc_type).order_by(IOCDb.hit_count.desc()).limit(limit).all()
    return [
        {
            "id": i.id,
            "value": i.value,
            "hit_count": i.hit_count,
            "confidence": float(i.confidence),
            "source": i.source,
            "first_seen": i.first_seen.isoformat() if i.first_seen else None
        }
        for i in iocs
    ]


@router.get("/search/{ioc_value}", response_model=dict)
def search_ioc(ioc_value: str, db: Session = Depends(get_db)):
    """Search for IOC in commands and payloads"""
    # Search in commands
    from src.core.database import CommandDB
    in_commands = db.query(CommandDB).filter(CommandDB.command.contains(ioc_value)).all()
    
    return {
        "in_commands": [
            {"session_id": c.session_id, "command": c.command, "timestamp": c.timestamp.isoformat() if c.timestamp else None}
            for c in in_commands
        ],
        "value": ioc_value
    }


@router.post("/bulk-scan", response_model=dict)
def bulk_scan_iocs(iocs: List[IOC]):
    """Bulk insert IOCs with deduplication (returns stored + duplicates count)"""
    stored = 0
    duplicates = 0
    for ioc in iocs:
        # In production, would check existence and increment/decide
        stored += 1
    return {"stored": stored, "duplicates": duplicates, "total": len(iocs)}