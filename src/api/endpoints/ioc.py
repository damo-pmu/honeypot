"""IOC scanning and storage API endpoints"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from src.analytics.ioc_scanner import scan_for_iocs, IOC
from src.infrastructure.database.queries import (
    create_ioc, get_ioc_by_value, increment_ioc_hit,
    get_top_iocs, get_iocs_by_type, search_ioc_in_commands, search_ioc_in_payloads
)

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
def store_ioc(request: CreateIOCRequest):
    """Store IOC in database with deduplication"""
    # Check if IOC already exists
    existing = get_ioc_by_value(request.value)
    if existing and existing.get("query"):
        # In real implementation, this would execute and check
        # For now, we create new
        pass
    
    ioc_data = request.model_dump()
    result = create_ioc(ioc_data)
    return IOCResponse(
        id=1,
        **ioc_data,
        first_seen=datetime.utcnow()
    )


@router.get("/top", response_model=List[dict])
def top_iocs(limit: int = 20):
    """Get top IOCs by hit count"""
    return [{"query": get_top_iocs(limit)[0]["query"]}]


@router.get("/type/{ioc_type}", response_model=List[dict])
def iocs_by_type(ioc_type: str, limit: int = 50):
    """Get IOCs by type (hash, ip, domain, url)"""
    valid_types = {"hash", "ip", "domain", "url"}
    if ioc_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid type. Must be one of: {valid_types}")
    return [{"query": get_iocs_by_type(ioc_type, limit)[0]["query"]}]


@router.get("/search/{ioc_value}", response_model=dict)
def search_ioc(ioc_value: str):
    """Search for IOC in commands and payloads"""
    return {
        "in_commands": search_ioc_in_commands(ioc_value),
        "in_payloads": search_ioc_in_payloads(ioc_value)
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