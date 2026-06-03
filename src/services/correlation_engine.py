"""Correlation Engine - Connect related attack entities"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from sqlalchemy.orm import Session


class CorrelationEngine:
    """
    Build correlations between:
    - Attacker IPs
    - Sessions  
    - Commands
    - Payloads
    - IOCs
    - Campaigns
    """
    
    def __init__(self, db: Session):
        self.db = db
    
    def build_graph(self, session_id: str) -> Dict[str, Any]:
        """Build full correlation graph for a session"""
        from src.core.database import AttackDB, CommandDB, SessionDB, IOCDb
        
        # Get session
        session = self.db.query(SessionDB).filter(SessionDB.id == session_id).first()
        if not session:
            return {"nodes": [], "edges": []}
        
        nodes = []
        edges = []
        
        # Attacker node
        nodes.append({
            "id": session.attacker_ip,
            "type": "attacker",
            "label": session.attacker_ip
        })
        
        # Session node
        nodes.append({
            "id": session_id,
            "type": "session",
            "label": f"Session {session_id[:8]}"
        })
        
        edges.append({"source": session.attacker_ip, "target": session_id, "type": "uses"})
        
        # Commands
        commands = self.db.query(CommandDB).filter(CommandDB.session_id == session_id).all()
        for cmd in commands[:20]:  # Limit
            cmd_id = f"cmd_{cmd.id}"
            nodes.append({
                "id": cmd_id,
                "type": "command",
                "label": cmd.command[:30] if cmd.command else "cmd"
            })
            edges.append({"source": session_id, "target": cmd_id, "type": "executes"})
        
        # Attacks/IOCs
        attacks = self.db.query(AttackDB).filter(AttackDB.session_id == session_id).all()
        for attack in attacks[:10]:
            if attack.ioc_value:
                ioc_node = f"ioc_{attack.ioc_value}"
                nodes.append({
                    "id": ioc_node,
                    "type": "ioc",
                    "label": attack.ioc_value[:30]
                })
                edges.append({"source": session_id, "target": ioc_node, "type": "contains"})
        
        return {"nodes": nodes, "edges": edges}
    
    def find_related_sessions(self, ip: str, hours: int = 24) -> List[str]:
        """Find sessions using same IP or related infrastructure"""
        from src.core.database import SessionDB, IOCDb
        
        # Direct IP matches
        direct = [s.id for s in self.db.query(SessionDB).filter(
            SessionDB.attacker_ip == ip
        ).limit(50).all()]
        
        # Related IPs (same payload/hash/domain)
        attacks = self.db.query(AttackDB).filter(AttackDB.attacker_ip == ip).all()
        
        related = set(direct)
        for attack in attacks:
            if attack.payload:
                sessions = [s.session_id for s in self.db.query(AttackDB).filter(
                    AttackDB.payload == attack.payload
                ).limit(20).all()]
                related.update(sessions)
        
        return list(related)[:50]