"""Campaign Detection Engine - Cluster attacks by shared indicators"""
from typing import Dict, Any, List, Optional
from collections import defaultdict
from datetime import datetime, timezone, timedelta, timezone

from sqlalchemy.orm import Session
from src.core.database import AttackDB


class CampaignEngine:
    """
    Detect attack campaigns by clustering on shared IOCs.
    
    Campaign = N unique IPs sharing same payload/hash/domain.
    Thresholds configurable (default: 10+ IPs = campaign).
    """
    
    CAMPAIGN_THRESHOLD = 10  # Min unique source IPs to qualify as campaign
    
    def __init__(self, db: Session):
        self.db = db
    
    def detect_campaigns(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Find campaigns in recent attacks"""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        attacks = self.db.query(AttackDB).filter(
            AttackDB.timestamp >= cutoff
        ).all()
        
        payload_groups = defaultdict(set)
        domain_groups = defaultdict(set)
        
        for attack in attacks:
            if attack.payload:
                payload_groups[attack.payload].add(attack.attacker_ip)
            if attack.ioc_type == "domain" and attack.ioc_value:
                domain_groups[attack.ioc_value].add(attack.attacker_ip)
        
        campaigns = []
        
        for payload, ips in payload_groups.items():
            if len(ips) >= self.CAMPAIGN_THRESHOLD:
                campaigns.append({
                    "type": "payload",
                    "indicator": payload[:50] if payload else "unknown",
                    "unique_ips": len(ips),
                    "ips": list(ips)[:20],
                    "severity": "high" if len(ips) > 50 else "medium"
                })
        
        for domain, ips in domain_groups.items():
            if len(ips) >= self.CAMPAIGN_THRESHOLD:
                campaigns.append({
                    "type": "domain",
                    "indicator": domain,
                    "unique_ips": len(ips),
                    "ips": list(ips)[:20],
                    "severity": "medium"
                })
        
        return campaigns[:50]