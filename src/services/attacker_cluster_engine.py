"""Attacker Clustering Engine - Group similar attacker behaviors"""
from typing import Dict, Any, List, Optional
from collections import defaultdict
from datetime import datetime, timezone, timedelta, timezone
import hashlib

from sqlalchemy.orm import Session


class AttackerClusterEngine:
    """
    Cluster attackers by behavioral patterns.
    
    Clusters based on:
    - Commands used
    - Payloads downloaded
    - Timing patterns
    """
    
    SIMILARITY_THRESHOLD = 0.7  # 70% pattern match = same cluster
    
    def __init__(self, db: Session):
        self.db = db
    
    def cluster_attackers(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Group attackers by behavior similarity"""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        # Get attackers with their commands/payloads
        attackers = self._get_attacker_behaviors(cutoff)
        
        clusters = []
        assigned = set()
        
        for ip, behaviors in attackers.items():
            if ip in assigned:
                continue
            
            # Find similar attackers
            similar = []
            behavior_hash = self._hash_behaviors(behaviors)
            
            for other_ip, other_behaviors in attackers.items():
                if other_ip in assigned or other_ip == ip:
                    continue
                
                similarity = self._calculate_similarity(behaviors, other_behaviors)
                if similarity >= self.SIMILARITY_THRESHOLD:
                    similar.append(other_ip)
            
            if len(similar) >= 3:  # Minimum cluster size
                cluster_id = hashlib.md5(f"{ip}:{''.join(sorted(similar))}").hexdigest()[:8]
                
                clusters.append({
                    "cluster_id": f"C{cluster_id}",
                    "primary_ip": ip,
                    "members": [ip] + similar[:10],
                    "size": len(similar) + 1,
                    "common_commands": list(behaviors.get("commands", [])),
                    "common_payloads": list(behaviors.get("payloads", [])),
                    "pattern_score": len(similar)
                })
        
        return sorted(clusters, key=lambda c: c["size"], reverse=True)
    
    def _get_attacker_behaviors(self, cutoff: datetime) -> Dict[str, Dict]:
        """Extract behavior patterns per IP"""
        from src.core.database import AttackDB, CommandDB
        
        result = defaultdict(lambda: {"commands": set(), "payloads": set()})
        
        # Get commands per attacker
        commands = self.db.query(CommandDB).filter(
            CommandDB.timestamp >= cutoff
        ).all()
        
        for cmd in commands:
            if cmd.attacker_ip:
                result[cmd.attacker_ip]["commands"].add(cmd.command[:50] if cmd.command else "")
        
        # Get payloads per attacker
        attacks = self.db.query(AttackDB).filter(
            AttackDB.timestamp >= cutoff,
            AttackDB.attack_type == "MALWARE_DOWNLOAD"
        ).all()
        
        for attack in attacks:
            if attack.attacker_ip and attack.payload:
                result[attack.attacker_ip]["payloads"].add(attack.payload[:100] if attack.payload else "")
        
        return result
    
    def _hash_behaviors(self, behaviors: Dict) -> str:
        """Create hash of behavior patterns"""
        combined = f"{''.join(sorted(behaviors['commands']))}{''.join(sorted(behaviors['payloads']))}"
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def _calculate_similarity(self, b1: Dict, b2: Dict) -> float:
        """Calculate similarity score between two behavior sets"""
        c1, p1 = b1.get("commands", set()), b1.get("payloads", set())
        c2, p2 = b2.get("commands", set()), b2.get("payloads", set())
        
        # Jaccard similarity
        cmd_sim = len(c1 & c2) / len(c1 | c2) if (c1 | c2) else 0
        payload_sim = len(p1 & p2) / len(p1 | p2) if (p1 | p2) else 0
        
        return (cmd_sim * 0.7 + payload_sim * 0.3)