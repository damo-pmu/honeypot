"""Analytics queries API - read-only database access"""
from fastapi import APIRouter

router = APIRouter(prefix="/analytics", tags=["analytics"])

@router.get("/top-attackers")
def top_attackers(limit: int = 10):
    """Get top attacker IPs"""
    from src.infrastructure.database.queries import get_top_attackers
    return {"query": get_top_attackers(limit)["query"], "limit": limit}

@router.get("/flagged-commands")
def flagged_commands():
    """Get flagged suspicious commands"""
    from src.infrastructure.database.queries import get_flagged_commands
    return {"query": get_flagged_commands()["query"]}

@router.get("/timeline")
def attack_timeline(hours: int = 24):
    """Get attack timeline"""
    from src.infrastructure.database.queries import get_attack_timeline
    return {"query": get_attack_timeline(hours)["query"], "hours": hours}