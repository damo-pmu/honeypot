"""Dashboard endpoints - Refactored for SOC template architecture
Clean separation: Python routes <<>> Jinja2 templates <<>> Alpine.js/HTMX frontend
"""
import os
import asyncio
import json
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Depends, Request, Response, Body
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func
from collections import Counter

# Templates setup - use Jinja2 env directly to avoid Starlette cache issues
from jinja2 import Environment, FileSystemLoader, select_autoescape

jinja_env = Environment(
    loader=FileSystemLoader("/app/src/templates"),
    autoescape=select_autoescape(["html", "xml"]),
    # remove enable_async - use sync render in FastAPI async context
)
# Disable bytecode cache to avoid unhashable dict errors
jinja_env.bytecode_cache = None

# Helper function to render template directly
def render_template(template_name: str, context: dict, status_code: int = 200, headers: dict = None) -> HTMLResponse:
    """Render Jinja2 template directly without cache issues."""
    tmpl = jinja_env.get_template(template_name)
    html = tmpl.render(**context)
    return HTMLResponse(html, status_code=status_code, headers=headers)

# Session auth
from src.api.middleware.session import (
    create_session, get_session, clear_session, require_auth,
    DASHBOARD_PASSWORD, _sessions
)

# Database
from src.core.database import get_db, SessionDB, AttackDB, CommandDB, AttackerDB

# Services
from src.services.dashboard import DashboardService, DashboardRepository
from src.utils.audit_logger import log_auth_event, log_dashboard_event

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

# In-memory event store (use Redis in production)
_dashboard_events: List[dict] = []
_event_counts: Counter = Counter()  # Track attack types


# ============================================================
# Event Broadcasting
# ============================================================
def add_event(event_type: str, data: dict) -> None:
    """Add event to dashboard stream for SSE broadcasting"""
    from src.infrastructure.observability.metrics import attacks_total, sessions_active
    
    event = {
        "type": event_type,
        "data": data,
        "timestamp": datetime.utcnow().isoformat()
    }
    _dashboard_events.append(event)
    _event_counts[event_type] += 1
    
    # Prometheus metrics
    protocol = data.get("protocol", "unknown")
    severity = data.get("severity", "medium")
    attacks_total.labels(protocol=protocol, type=event_type, severity=severity).inc()
    
    if "session_id" in data:
        sessions_active.inc()
    
    # Keep last 100 events
    if len(_dashboard_events) > 100:
        old = _dashboard_events.pop(0)
        _event_counts[old["type"]] -= 1
        if _event_counts[old["type"]] <= 0:
            del _event_counts[old["type"]]


def get_stats() -> dict:
    """Get current dashboard statistics"""
    return {
        "total_events": len(_dashboard_events),
        "attacks_24h": sum(_event_counts.values()),
        "unique_ips_24h": len(set(e.get("data", {}).get("attacker_ip") for e in _dashboard_events[-100:] if e.get("data", {}).get("attacker_ip"))),
        "active_sessions": len(_sessions)
    }


# ============================================================
# UI Routes (templated)
# ============================================================
@router.get("/")
def dashboard_home(request: Request):
    """Serve dashboard HTML via Jinja2 template - redirect to login if no session"""
    if get_session(request):
        return render_template("dashboard.html", {"request": request, "stats": get_stats()})
    return render_template("login.html", {"request": request, "error": None})


@router.post("/login")
async def login(request: Request, response: Response):
    """Login with password form - returns dashboard HTML with session cookie"""
    form = await request.form()
    password = form.get("password", "")
    client_ip = request.client.host if request.client else "unknown"
    
    if password == DASHBOARD_PASSWORD:
        session = create_session(response)
        log_auth_event("login", True, client_ip, {"method": "form"})
        
        return render_template(
            "dashboard.html",
            {"request": request, "stats": get_stats()},
            headers={"Set-Cookie": f"dash_session={session}; HttpOnly; Path=/; SameSite=strict"}
        )
    
    log_auth_event("login_failed", False, client_ip, {"reason": "invalid_password"})
    return render_template(
        "login.html",
        {"request": request, "error": "Invalid access key"},
        status_code=401
    )


@router.get("/logout")
def logout(request: Request, response: Response):
    """Logout and clear session"""
    session = get_session(request)
    client_ip = request.client.host if request.client else "unknown"
    
    if session:
        clear_session(response, session)
        log_auth_event("logout", True, client_ip, {})
    
    return RedirectResponse("/dashboard/", status_code=303)


# ============================================================
# API Routes (JSON)
# ============================================================
@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Get dashboard statistics - combines Prometheus + DB data"""
    service = DashboardService(db)
    db_stats = service.get_live_stats()
    
    # Merge with in-memory event counts for frontend format
    return {
        "total_events": len(_dashboard_events),
        "attacks_24h": sum(_event_counts.values()),
        "unique_ips_24h": len(set(e.get("data", {}).get("attacker_ip") for e in _dashboard_events[-100:] if e.get("data", {}).get("attacker_ip"))),
        "active_sessions": len(_sessions),
        **db_stats
    }


@router.get("/api/sessions")
def get_sessions(
    request: Request,
    db: Session = Depends(get_db),
    protocol: Optional[str] = None,
    ip: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    """Get sessions list with optional filtering - HTMX compatible partial rendering"""
    query = db.query(SessionDB)
    
    if protocol:
        query = query.filter(SessionDB.protocol == protocol)
    if ip:
        query = query.filter(SessionDB.attacker_ip == ip)
    
    sessions = query.order_by(SessionDB.start_time.desc()).limit(limit).offset(offset).all()
    
    return [
        {
            "id": s.id,
            "attacker_ip": s.attacker_ip,
            "protocol": s.protocol,
            "start_time": s.start_time.isoformat() if s.start_time else None,
            "end_time": s.end_time.isoformat() if s.end_time else None,
            "duration_seconds": s.duration_seconds,
            "interaction_count": s.interaction_count
        }
        for s in sessions
    ]


@router.get("/api/sessions/{session_id}")
def get_session_detail(session_id: str, db: Session = Depends(get_db)):
    """Get full session aggregation for investigation panel"""
    session = db.query(SessionDB).filter(SessionDB.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Get attacker info
    attacker = db.query(AttackerDB).filter(AttackerDB.ip == session.attacker_ip).first()
    
    # Get attacks
    attacks = db.query(AttackDB).filter(
        AttackDB.session_id == session_id
    ).order_by(AttackDB.timestamp).all()
    
    # Get commands
    commands = db.query(CommandDB).filter(
        CommandDB.session_id == session_id
    ).order_by(CommandDB.timestamp).all()
    
    # Build timeline
    timeline = []
    for a in attacks:
        timeline.append({
            "type": "attack",
            "timestamp": a.timestamp.isoformat(),
            "data": {
                "attack_type": a.attack_type,
                "protocol": a.protocol,
                "severity": a.severity,
                "attacker_ip": a.attacker_ip
            }
        })
    for c in commands:
        timeline.append({
            "type": "command",
            "timestamp": c.timestamp.isoformat(),
            "data": {
                "command": c.command,
                "is_flagged": c.flagged,
                "attacker_ip": c.attacker_ip
            }
        })
    
    timeline.sort(key=lambda x: x["timestamp"])
    
    return {
        "id": session.id,
        "attacker_ip": session.attacker_ip,
        "protocol": session.protocol,
        "start_time": session.start_time.isoformat() if session.start_time else None,
        "end_time": session.end_time.isoformat() if session.end_time else None,
        "duration_seconds": session.duration_seconds,
        "geoip": attacker.geoip if attacker else None,
        "threat_score": attacker.threat_score if attacker else 0,
        "commands": [
            {"command": c.command, "flagged": c.flagged, "timestamp": c.timestamp.isoformat()}
            for c in commands
        ],
        "attacks": [
            {"attack_type": a.attack_type, "severity": a.severity, "payload": a.payload}
            for a in attacks
        ],
        "timeline": timeline
    }


@router.get("/stream")
async def stream(request: Request, session: Optional[str] = Depends(get_session)):
    """Server-sent events stream - optional auth for public demo mode"""
    
    async def event_generator():
        # Send existing events
        for event in _dashboard_events[-20:]:
            yield f"data: {json.dumps(event)}\\n\\n"
        
        # Stream new events
        last_id = len(_dashboard_events)
        while True:
            if await request.is_disconnected():
                break
            
            while last_id < len(_dashboard_events):
                yield f"data: {json.dumps(_dashboard_events[last_id])}\\n\\n"
                last_id += 1
            
            await asyncio.sleep(0.5)
    
    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/events/recent")
def get_recent_events(session: str = Depends(require_auth), limit: int = 20):
    """Get recent events - requires session"""
    return _dashboard_events[-limit:]


# ============================================================
# Internal API (no auth)
# ============================================================
class EventRequest(BaseModel):
    event_type: str
    data: dict


@router.post("/emit")
def emit_event_json(request: EventRequest):
    """Emit event via JSON body (no auth for internal worker)"""
    add_event(request.event_type, request.data)
    return {"status": "emitted"}


@router.get("/debug/status")
def debug_status():
    """Debug endpoint - system status for autonomous debugging"""
    return {
        "events_pending": len(_dashboard_events),
        "event_types": dict(_event_counts),
        "sessions_active": len(_sessions),
        "memory_usage": "ok"
    }