"""IOC (Indicators of Compromise) scanning module"""
import re
from typing import List, Dict
from pydantic import BaseModel

class IOC(BaseModel):
    ioc_type: str  # hash, ip, domain, url
    value: str
    confidence: float = 1.0
    source: str = "scan"

HASH_PATTERNS = re.compile(r'\b[a-fA-F0-9]{32,64}\b')
IP_PATTERNS = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URL_PATTERNS = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
HASH_KEYWORD_PATTERNS = re.compile(r'\b(?:sha1|sha256|md5|sha1sum|sha256sum|md5sum)[: ]+([a-fA-F0-9]{6,64})\b', re.IGNORECASE)

def extract_hashes(data: str) -> List[IOC]:
    """Extract hash IOCs (MD5, SHA1, SHA256)"""
    hashes = set(HASH_PATTERNS.findall(data))
    hashes.update(HASH_KEYWORD_PATTERNS.findall(data))
    return [
        IOC(ioc_type="hash", value=h)
        for h in hashes
    ]

def extract_ips(data: str) -> List[IOC]:
    """Extract IP IOCs"""
    return [
        IOC(ioc_type="ip", value=ip)
        for ip in set(IP_PATTERNS.findall(data))
    ]

def extract_urls(data: str) -> List[IOC]:
    """Extract URL IOCs"""
    return [
        IOC(ioc_type="url", value=url)
        for url in set(URL_PATTERNS.findall(data))
    ]

def scan_for_iocs(text: str) -> Dict[str, List[IOC]]:
    """Full IOC scan on text"""
    return {
        "hashes": extract_hashes(text),
        "ips": extract_ips(text),
        "urls": extract_urls(text),
        "total": len(extract_hashes(text)) + len(extract_ips(text)) + len(extract_urls(text))
    }