"""Database repository layer - PostgreSQL ready"""
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

class DBSession(BaseModel):
    """Database session model for raw queries"""
    id: int
    attacker_ip: str
    protocol: str
    start_time: datetime
    interaction_count: int

class DBCommand(BaseModel):
    """Database command model"""
    id: int
    session_id: int
    command: str
    flagged: bool

def get_top_attackers(limit: int = 10) -> List[dict]:
    """Top IPs by attack frequency"""
    query = f"""
    SELECT attacker_ip, COUNT(*) as attack_count
    FROM sessions
    GROUP BY attacker_ip
    ORDER BY attack_count DESC
    LIMIT {limit};
    """
    return {"query": query, "note": "Execute via SQLAlchemy session"}

def get_flagged_commands() -> List[dict]:
    """Get all flagged suspicious commands"""
    query = """
    SELECT c.command, s.attacker_ip, c.timestamp
    FROM commands c
    JOIN sessions s ON c.session_id = s.id
    WHERE c.flagged = true
    ORDER BY c.timestamp DESC;
    """
    return {"query": query}

def get_attack_timeline(hours: int = 24) -> List[dict]:
    """Timeline of attacks for last N hours"""
    query = f"""
    SELECT 
        DATE_TRUNC('hour', start_time) as hour,
        COUNT(*) as attacks,
        AVG(threat_score) as avg_score
    FROM sessions s
    JOIN attackers a ON s.attacker_ip = a.ip
    WHERE start_time > NOW() - INTERVAL '{hours} hours'
    GROUP BY hour
    ORDER BY hour DESC;
    """
    return {"query": query}