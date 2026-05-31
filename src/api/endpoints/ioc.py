"""IOC scanning API endpoint"""
from fastapi import APIRouter
from pydantic import BaseModel
from src.analytics.ioc_scanner import scan_for_iocs

router = APIRouter(prefix="/ioc", tags=["ioc"])

class ScanRequest(BaseModel):
    text: str

@router.post("/scan")
def scan_iocs(request: ScanRequest):
    """Scan text for IOCs (hashes, IPs, URLs)"""
    return scan_for_iocs(request.text)