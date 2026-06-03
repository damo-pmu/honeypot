"""Investigation Graph Builder - Neo4j-style graph for attack relationships"""
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class GraphNode:
    """Graph node entity"""
    id: str
    type: str  # attacker, session, command, payload, ioc, campaign
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass  
class GraphEdge:
    """Graph edge relationship"""
    source: str
    target: str
    relationship: str


class GraphBuilder:
    """
    Build investigation graph showing relationships.
    
    Graph structure:
    Attacker → Session → Command → Payload
                        ↓
                    IOC ← Campaign
    """
    
    def __init__(self, db):
        self.db = db
    
    def build_for_session(self, session_id: str) -> Dict[str, Any]:
        """Build graph centered on a session"""
        from src.core.database import AttackDB, CommandDB, SessionDB, IOCDb
        
        nodes = []
        edges = []
        
        # Get session
        session = self.db.query(SessionDB).filter(SessionDB.id == session_id).first()
        if not session:
            return {"nodes": nodes, "edges": edges}
        
        # Add attacker node
        nodes.append(GraphNode(
            id=f"ip_{session.attacker_ip}",
            type="attacker",
            label=session.attacker_ip,
            properties={"country": session.attacker_ip}  # Would be enriched
        ).__dict__)
        
        # Add session node
        nodes.append(GraphNode(
            id=f"session_{session_id}",
            type="session",
            label=f"Session {session_id[:8]}",
            properties={"protocol": session.protocol}
        ).__dict__)
        
        edges.append(GraphEdge(
            source=f"ip_{session.attacker_ip}",
            target=f"session_{session_id}",
            relationship="initiates"
        ).__dict__)
        
        # Add commands
        commands = self.db.query(CommandDB).filter(CommandDB.session_id == session_id).all()
        for cmd in commands[:30]:
            cmd_id = f"cmd_{cmd.id}"
            nodes.append(GraphNode(
                id=cmd_id,
                type="command",
                label=cmd.command[:40] if cmd.command else "cmd",
                properties={"flagged": cmd.flagged}
            ).__dict__)
            
            edges.append(GraphEdge(
                source=f"session_{session_id}",
                target=cmd_id,
                relationship="executes"
            ).__dict__)
        
        # Add payloads
        attacks = self.db.query(AttackDB).filter(AttackDB.session_id == session_id).all()
        for attack in attacks:
            if attack.payload and len(attack.payload) > 20:
                payload_id = f"payload_{attack.id}"
                nodes.append(GraphNode(
                    id=payload_id,
                    type="payload",
                    label=f"Payload ({len(attack.payload)}b)",
                    properties={"attack_type": attack.attack_type}
                ).__dict__)
                
                edges.append(GraphEdge(
                    source=f"session_{session_id}",
                    target=payload_id,
                    relationship="downloads"
                ).__dict__)
        
        return {"nodes": nodes, "edges": edges}
    
    def build_for_campaign(self, campaign_indicator: str) -> Dict[str, Any]:
        """Build graph for campaign investigation"""
        # Would query CampaignDB when implemented
        return {"nodes": [], "edges": []}