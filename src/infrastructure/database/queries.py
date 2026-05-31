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


# IOC Database Queries
def create_ioc(ioc: dict) -> dict:
    """Create new IOC indicator in database"""
    query = f"""
    INSERT INTO ioc_indicators (ioc_type, value, confidence, source, related_attacker_ip, related_session_id)
    VALUES ('{ioc['ioc_type']}', '{ioc['value']}', {ioc.get('confidence', 1.0)}, 
            '{ioc.get('source', 'scan')}', '{ioc.get('related_attacker_ip', '')}', '{ioc.get('related_session_id', '')}')
    RETURNING id, value, hit_count;
    """
    return {"query": query, "operation": "INSERT"}


def get_ioc_by_value(value: str) -> Optional[dict]:
    """Get IOC by value - used for deduplication"""
    query = f"""
    SELECT id, ioc_type, value, hit_count, confidence, source, first_seen, last_seen
    FROM ioc_indicators 
    WHERE value = '{value}';
    """
    return {"query": query, "operation": "SELECT"}


def increment_ioc_hit(ioc_id: int) -> dict:
    """Increment hit count and update last_seen for existing IOC"""
    query = f"""
    UPDATE ioc_indicators 
    SET hit_count = hit_count + 1, last_seen = NOW()
    WHERE id = {ioc_id}
    RETURNING hit_count;
    """
    return {"query": query, "operation": "UPDATE"}


def get_top_iocs(limit: int = 20) -> List[dict]:
    """Get top IOCs by hit count"""
    query = f"""
    SELECT ioc_type, value, hit_count, source, first_seen
    FROM ioc_indicators
    ORDER BY hit_count DESC
    LIMIT {limit};
    """
    return [{"query": query}]


def get_iocs_by_type(ioc_type: str, limit: int = 50) -> List[dict]:
    """Get IOCs filtered by type"""
    query = f"""
    SELECT id, value, hit_count, confidence, source, first_seen, last_seen
    FROM ioc_indicators
    WHERE ioc_type = '{ioc_type}'
    ORDER BY hit_count DESC
    LIMIT {limit};
    """
    return [{"query": query}]


def search_ioc_in_commands(ioc_value: str) -> List[dict]:
    """Find commands containing this IOC value"""
    query = f"""
    SELECT session_id, command, timestamp
    FROM commands
    WHERE command ILIKE '%{ioc_value}%'
    ORDER BY timestamp DESC;
    """
    return [{"query": query}]


def search_ioc_in_payloads(ioc_value: str) -> List[dict]:
    """Find attack payloads containing this IOC value"""
    query = f"""
    SELECT session_id, attack_type, payload, timestamp
    FROM attacks
    WHERE payload ILIKE '%{ioc_value}%'
    ORDER BY timestamp DESC;
    """
    return [{"query": query}]