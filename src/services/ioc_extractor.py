"""IOC Extraction Engine - Extract threat indicators from payloads and commands"""
import re
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass


# IOC regex patterns
IOC_PATTERNS = {
    "ipv4": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{1,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
    "url": r'https?://(?:[-\w.])+(?:[:\d]+)?/(?:[^\s]*)?',
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "telegram": r'(?:t\.me/|@tg|telegram\.me/|/telegram/)([a-zA-Z0-9_-]+)',
    "discord": r'(?:discord\.gg/|discordapp\.com/invite/)([a-zA-Z0-9-]+)',
    "wallet_btc": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
    "wallet_eth": r'\b0x[a-fA-F0-9]{40}\b',
}


@dataclass
class IOC:
    """Extracted indicator of compromise"""
    value: str
    ioc_type: str
    confidence: float = 1.0
    context: Optional[str] = None
    source_event_id: Optional[str] = None


class IOCExtractor:
    """
    Extract IOCs from attack payloads and commands.
    
    Supports: IP, Domain, URL, Hash (SHA256/MD5), Email, Telegram, Discord, Crypto wallets
    """
    
    def __init__(self, text: str, event_id: Optional[str] = None):
        self.text = text or ""
        self.event_id = event_id
    
    def extract(self) -> List[IOC]:
        """Extract all IOC types from text"""
        iocs = []
        seen = set()
        
        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = re.findall(pattern, self.text, re.IGNORECASE)
            
            for match in matches:
                # Normalize match
                value = match if isinstance(match, str) else match[0] if isinstance(match, tuple) else match
                
                # Skip if already seen
                key = f"{ioc_type}:{value}"
                if key in seen:
                    continue
                seen.add(key)
                
                iocs.append(IOC(
                    value=value,
                    ioc_type=ioc_type,
                    context=self.text[:100],
                    source_event_id=self.event_id
                ))
        
        return iocs
    
    def get_unique(self) -> Dict[str, List[str]]:
        """Get unique IOCs grouped by type"""
        iocs = self.extract()
        result = {}
        
        for ioc in iocs:
            if ioc.ioc_type not in result:
                result[ioc.ioc_type] = []
            if ioc.value not in result[ioc.ioc_type]:
                result[ioc.ioc_type].append(ioc.value)
        
        return result


class IOCService:
    """
    Service to extract and store IOCs from events.
    Uses BackgroundTasks for heavy extraction without blocking.
    """
    
    def __init__(self, db):
        self.db = db
    
    def extract_from_event(self, event: Dict[str, Any]) -> List[IOC]:
        """Extract IOCs from a single event"""
        payload = event.get("data", {}).get("payload", "") or ""
        command = event.get("data", {}).get("command", "") or ""
        text = f"{payload} {command}"
        
        extractor = IOCExtractor(text, event.get("id"))
        return extractor.extract()
    
    def extract_from_session(self, session_id: str, events: List[Dict[str, Any]]) -> List[IOC]:
        """Extract IOCs from all events in session"""
        all_iocs = []
        seen = set()
        
        for event in events:
            iocs = self.extract_from_event(event)
            for ioc in iocs:
                key = f"{ioc.ioc_type}:{ioc.value}"
                if key not in seen:
                    seen.add(key)
                    all_iocs.append(ioc)
        
        return all_iocs