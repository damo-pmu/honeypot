"""Campaign Detection Engine - Cluster attacks by shared indicators"""
from typing import Dict, Any, List, Optional
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from src.repositories.attack_repository import AttackRepository
from src.repositories.ioc_repository import IOCRepository


class CampaignEngine:
    """
    Detect attack campaigns by clustering on shared IOCs.
    
    Campaign = N unique IPs sharing same payload/hash/domain.
    Thresholds configurable (default: 10+ IPs = campaign).
    """
    
    CAMPAIGN_THRESHOLD = 10  # Min unique source IPs to qualify as campaign
    
    def __init__(self, db: Session):
        self.db = db
        self.attack_repo = AttackRepository(db)
        self.ioc_repo = IOCRepository(db)
    
    def detect_campaigns(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Find campaigns in recent attacks"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Get recent attacks with payloads
        attacks = self.db.query(AttackDB).filter(
            AttackDB.timestamp >= cutoff
        ).all()
        
        # Group by payload/hash/domain
        payload_groups = defaultdict(set)
        domain_groups = defaultdict(set)
        ip_groups = defaultdict(set)
        
        for attack in attacks:
            if attack.payload:
                payload_groups[attack.payload].add(attack.attacker_ip)
            if attack.ioc_type == "domain" and attack.ioc_value:
                domain_groups[attack.ioc_value].add(attack.attacker_ip)
            ip_groups[attack.attacker_ip].add(attack.session_id)
        
        campaigns = []
        
        # Check payload campaigns
        for payload, ips in payload_groups.items():
            if len(ips) >= self.CAMPAIGN_THRESHOLD:
                campaigns.append({
                    "type": "payload",
                    "indicator": payload[:50],
                    "unique_ips": len(ips),
                    "ips": list(ips)[:20],  # Sample
                    "severity": "high" if len(ips) > 50 else "medium"
                })
        
        # Check domain campaigns
        for domain, ips in domain_groups.items():
            if len(ips) >= self.CAMPAIGN_THRESHOLD:
                campaigns.append({
                    "type": "domain",
                    "indicator": domain,
                    "unique_ips": len(ips),
                    "ips": list(ips)[:20],
                    "severity": "medium"
                })
        
        return campaigns[:50]  # Top 50 campaigns
    
    def get_related_sessions(self, indicator: str, ioc_type: str) -> List[str]:
        """Get all sessions using same indicator"""
        return self.attack_repo.get_sessions_by_ioc(indicator, ioc_type)