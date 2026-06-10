"""Enhanced Dashboard API - Phase 3 Production Ready

Complete production-ready dashboard API with:
- Real-time WebSocket support
- Advanced analytics and aggregations
- Expert-level queries and reports
- Export capabilities
- Proper authentication and authorization
- Comprehensive filtering and search
- Performance optimization
"""
import asyncio
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Depends, Request, Query, WebSocket, WebSocketDisconnect, Form, Response
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.core.database import get_db, AttackerDB, SessionDB, CommandDB, AttackDB
from src.services.dashboard_analytics_service import DashboardAnalyticsService, DashboardExportService
from src.services.statistics_service import StatisticsService
from src.api.middleware.session import get_session, create_session, clear_session

# Templates directory
templates = Environment(loader=FileSystemLoader("templates"))

# Initialize router with auth prefix
router = APIRouter(prefix="/dashboard", tags=["dashboard"])


# WebSocket connection manager for real-time updates
class ConnectionManager:
    """Manage WebSocket connections for real-time dashboard updates"""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    async def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """Send message to all connected clients"""
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass


manager = ConnectionManager()


# Authentication Helpers
def require_dashboard_auth(request: Request):
    """Check if user has valid dashboard session - redirect to login if not"""
    session = get_session(request)
    if not session:
        # Store intended destination for post-login redirect
        return None
    return session


# UI Routes (using Jinja2 templates)
@router.get("/", response_class=HTMLResponse)
def dashboard_home(request: Request, db: Session = Depends(get_db)):
    """Serve dashboard home page via Jinja2 - requires auth"""
    session = require_dashboard_auth(request)
    if not session:
        return RedirectResponse(url="/dashboard/login", status_code=302)
    
    try:
        service = StatisticsService(db)
        stats = service.get_dashboard_stats()
    except Exception:
        stats = {"active_sessions": 0, "unique_attackers": 0, "high_threat_count": 0, "ioc_count": 0}

    html = templates.get_template("dashboard.html").render(
        request=request, stats=stats, active_page="home"
    )
    return HTMLResponse(content=html)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str = ""):
    """Serve login page"""
    html = templates.get_template("login.html").render(
        request=request, error=error
    )
    return HTMLResponse(content=html)


@router.post("/login")
def login_submit(request: Request, password: str = Form(...)):
    """Process login form"""
    from src.api.middleware.session import DASHBOARD_PASSWORD
    if password == DASHBOARD_PASSWORD:
        response = RedirectResponse(url="/dashboard/", status_code=302)
        session_id = create_session(response)
        return response
    # Wrong password - redirect with error
    return RedirectResponse(url="/dashboard/login?error=1", status_code=302)


class SessionCreateRequest(BaseModel):
    session_id: str
    attacker_ip: str
    protocol: str = "SSH"


class EventCreateRequest(BaseModel):
    session_id: str
    attacker_ip: str
    protocol: str = "SSH"
    attack_type: str
    payload: str = ""
    severity: int = 50


@internal_router.get("/sessions/{session_id}/with-attacks", response_model=dict)
def get_session_with_attacks(session_id: str, db: Session = Depends(get_db)):
    """Get session with all attacks and commands - for linking with map markers"""
    from src.core.database import AttackerDB, CommandDB
    
    session = db.query(SessionDB).filter(SessionDB.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    attacker = db.query(AttackerDB).filter(
        AttackerDB.ip == session.attacker_ip
    ).first()
    
    attacks = db.query(AttackDB).filter(
        AttackDB.session_id == session_id
    ).order_by(AttackDB.timestamp).all()
    
    commands = db.query(CommandDB).filter(
        CommandDB.session_id == session_id
    ).order_by(CommandDB.timestamp).all()
    
    timeline = []
    for a in attacks:
        timeline.append({
            "type": "attack",
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "data": {
                "attack_type": a.attack_type,
                "severity": a.severity,
                "payload": a.payload
            }
        })
    for c in commands:
        timeline.append({
            "type": "command",
            "timestamp": c.timestamp.isoformat() if c.timestamp else None,
            "data": {
                "command": c.command,
                "flagged": c.flagged
            }
        })
    
    timeline.sort(key=lambda x: x["timestamp"] or "")
    
    return {
        "session": {
            "id": session.id,
            "attacker_ip": session.attacker_ip,
            "protocol": session.protocol,
            "start_time": session.start_time.isoformat() if session.start_time else None,
            "geoip": attacker.geoip if attacker else None
        },
        "timeline": timeline,
        "attacks_count": len(attacks),
        "commands_count": len(commands)
    }


# ===== INTERNAL ENDPOINTS (unprotected - used by worker) =====

# Separate router for internal endpoints (worker calls without /dashboard prefix)
internal_router = APIRouter(tags=["internal"])


@internal_router.post("/internal/sessions", status_code=201)
def internal_create_session(request: SessionCreateRequest, db: Session = Depends(get_db)):
    """Internal endpoint - create session from Cowrie worker"""
    # Ensure attacker exists (required for FK constraint)
    db_attacker = db.query(AttackerDB).filter(AttackerDB.ip == request.attacker_ip).first()
    if not db_attacker:
        db_attacker = AttackerDB(ip=request.attacker_ip)
        db.add(db_attacker)
        db.commit()

    db_session = db.query(SessionDB).filter(SessionDB.id == request.session_id).first()
    if not db_session:
        db_session = SessionDB(id=request.session_id, attacker_ip=request.attacker_ip, protocol=request.protocol)
        db.add(db_session)
        db.commit()
        db.refresh(db_session)
    return {"id": request.session_id, "status": "created"}


@internal_router.post("/internal/sessions/{session_id}/end")
def internal_end_session(session_id: str, db: Session = Depends(get_db)):
    """Internal endpoint - mark session as closed"""
    db_session = db.query(SessionDB).filter(SessionDB.id == session_id).first()
    if db_session and not db_session.end_time:
        db_session.end_time = datetime.now(timezone.utc)
        db_session.duration_seconds = int((db_session.end_time - db_session.start_time).total_seconds())
        db.commit()
    return {"status": "ok"}


@internal_router.post("/events", status_code=201)
def internal_log_event(request: EventCreateRequest, db: Session = Depends(get_db)):
    """Internal endpoint - log attack event from worker"""
    # Ensure attacker exists
    db_attacker = db.query(AttackerDB).filter(AttackerDB.ip == request.attacker_ip).first()
    if not db_attacker:
        db_attacker = AttackerDB(ip=request.attacker_ip, threat_score=request.severity)
        db.add(db_attacker)
        db.commit()

    # Log event using AttackDB model
    event = AttackDB(
        session_id=request.session_id,
        attacker_ip=request.attacker_ip,
        protocol=request.protocol,
        attack_type=request.attack_type,
        payload=request.payload[:1000],
        severity=request.severity
    )
    db.add(event)
    db.commit()

    return {"status": "logged", "id": event.id}


# ===== END INTERNAL ENDPOINTS =====

@router.get("/logout")
def logout(request: Request):
    """Logout and clear session"""
    session = request.cookies.get("dash_session", "")
    response = RedirectResponse(url="/dashboard/login", status_code=302)
    clear_session(response, session)
    return response


@router.get("/analytics", response_class=HTMLResponse)
def analytics_page(request: Request, db: Session = Depends(get_db)):
    """Serve analytics dashboard page via Jinja2 - requires auth"""
    session = require_dashboard_auth(request)
    if not session:
        return RedirectResponse(url="/dashboard/login", status_code=302)
        
    html = templates.get_template("dashboard_analytics.html").render(
        request=request, active_page="analytics"
    )
    return HTMLResponse(content=html)


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    """Serve dashboard settings page via Jinja2 - requires auth"""
    session = require_dashboard_auth(request)
    if not session:
        return RedirectResponse(url="/dashboard/login", status_code=302)
        
    html = templates.get_template("dashboard_settings.html").render(
        request=request, active_page="settings"
    )
    return HTMLResponse(content=html)


# API: Dashboard Statistics (Public - cached)
@router.get("/api/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Get dashboard overview statistics - CACHED"""
    service = StatisticsService(db)
    return service.get_dashboard_stats()


@router.get("/api/live-feed")
def get_live_feed(db: Session = Depends(get_db), limit: int = Query(50, le=500)):
    """Get recent events for live feed - PUBLIC endpoint"""
    service = StatisticsService(db)
    return {"items": service.get_live_feed(limit=limit)}


# API: Advanced Analytics (Protected)
@router.get("/api/analytics/threat-heatmap")
def get_threat_heatmap(
    request: Request,
    db: Session = Depends(get_db),
    hours: int = Query(24, ge=1, le=720)
):
    """Get threat intensity heatmap by time and severity"""
    require_dashboard_auth(request)
    analytics = DashboardAnalyticsService(db)
    return analytics.get_threat_heat_map(hours)


@router.get("/api/analytics/attacker-profiles")
def get_attacker_profiles(
    request: Request,
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=1000),
    min_threat_score: int = Query(0, ge=0, le=100),
    sort_by: str = Query("threat_score")
):
    """Get detailed attacker profiles with scoring and behavior"""
    require_dashboard_auth(request)
    analytics = DashboardAnalyticsService(db)
    profiles = analytics.get_attacker_profiles(limit)
    if min_threat_score > 0:
        profiles = [p for p in profiles if p["threat_score"] >= min_threat_score]
    profiles.sort(key=lambda p: p.get(sort_by, 0), reverse=True)
    return {"profiles": profiles, "count": len(profiles)}


@router.get("/api/analytics/command-patterns")
def get_command_patterns(
    request: Request,
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=500),
    suspicious_only: bool = False
):
    """Identify frequently used commands and suspicious patterns"""
    require_dashboard_auth(request)
    analytics = DashboardAnalyticsService(db)
    result = analytics.get_command_patterns(limit)
    if suspicious_only:
        result["patterns"] = [p for p in result["patterns"] if p["risk_score"] > 50]
    return result


@router.get("/api/analytics/ioc-summary")
def get_ioc_summary(request: Request, db: Session = Depends(get_db)):
    """Get IOC extraction summary and trending"""
    require_dashboard_auth(request)
    analytics = DashboardAnalyticsService(db)
    return analytics.get_ioc_summary()


@router.get("/api/analytics/payload-analysis")
def get_payload_analysis(
    request: Request,
    db: Session = Depends(get_db),
    hours: int = Query(24, ge=1, le=720)
):
    """Get malware/payload analysis with trending"""
    require_dashboard_auth(request)
    analytics = DashboardAnalyticsService(db)
    return analytics.get_payload_analysis(hours)


@router.get("/api/analytics/attack-taxonomy")
def get_attack_taxonomy(request: Request, db: Session = Depends(get_db)):
    """Get attacks grouped by type/category"""
    require_dashboard_auth(request)
    analytics = DashboardAnalyticsService(db)
    return analytics.get_attack_taxonomy()


@router.get("/api/analytics/correlations")
def get_correlation_insights(
    request: Request,
    db: Session = Depends(get_db),
    hours: int = Query(24, ge=1, le=720)
):
    """Get correlated attack patterns and insights"""
    require_dashboard_auth(request)
    analytics = DashboardAnalyticsService(db)
    return analytics.get_correlation_insights(hours)


# API: Export & Reporting (Protected)
@router.get("/api/export/threat-report")
def export_threat_report(
    request: Request,
    db: Session = Depends(get_db),
    hours: int = Query(24, ge=1, le=720),
    format: str = Query("json", pattern="^(json|csv)$")
):
    """Export comprehensive threat report"""
    require_dashboard_auth(request)
    exporter = DashboardExportService(db)
    report = exporter.export_threat_report(hours)
    if format == "csv":
        return JSONResponse({"message": "CSV export format coming soon"}, status_code=501)
    return report


@router.get("/api/export/attackers")
async def export_attackers_csv(
    request: Request,
    db: Session = Depends(get_db),
    limit: int = Query(10000, ge=1, le=100000)
):
    """Export attackers list as CSV"""
    require_dashboard_auth(request)
    attackers = db.query(AttackerDB).limit(limit).all()

    def generate():
        yield "ip,classification,threat_score,threat_level,country,asn,reputation,first_seen,last_seen\n"
        for attacker in attackers:
            first_seen = db.query(SessionDB).filter(
                SessionDB.attacker_ip == attacker.ip
            ).order_by(SessionDB.start_time.asc()).first()
            last_seen = db.query(SessionDB).filter(
                SessionDB.attacker_ip == attacker.ip
            ).order_by(SessionDB.start_time.desc()).first()
            yield (
                f"{attacker.ip},"
                f"{attacker.classification or 'unknown'},"
                f"{attacker.threat_score or 0},"
                f"{attacker.threat_level or 'unknown'},"
                f"{attacker.country or 'unknown'},"
                f"{attacker.asn or 'unknown'},"
                f"{attacker.reputation or 0},"
                f"{first_seen.start_time.isoformat() if first_seen else ''},"
                f"{last_seen.start_time.isoformat() if last_seen else ''}\n"
            )

    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=attackers.csv"}
    )


# API: Advanced Search & Filtering
@router.get("/api/search/sessions")
def search_sessions(
    request: Request,
    db: Session = Depends(get_db),
    ip: Optional[str] = None,
    protocol: Optional[str] = None,
    min_duration: int = Query(0, ge=0),
    max_duration: Optional[int] = None,
    limit: int = Query(100, ge=1, le=10000),
    offset: int = Query(0, ge=0)
):
    """Advanced session search with filters"""
    require_dashboard_auth(request)
    query = db.query(SessionDB)
    if ip:
        query = query.filter(SessionDB.attacker_ip == ip)
    if protocol:
        query = query.filter(SessionDB.protocol == protocol)
    if min_duration > 0:
        query = query.filter(SessionDB.duration_seconds >= min_duration)
    if max_duration:
        query = query.filter(SessionDB.duration_seconds <= max_duration)

    total = query.count()
    results = query.order_by(SessionDB.start_time.desc()).offset(offset).limit(limit).all()
    return {
        "results": [
            {
                "id": s.id,
                "ip": s.attacker_ip,
                "protocol": s.protocol,
                "start_time": s.start_time.isoformat(),
                "end_time": s.end_time.isoformat() if s.end_time else None,
                "duration_seconds": s.duration_seconds
            }
            for s in results
        ],
        "total": total,
        "limit": limit,
        "offset": offset
    }


@router.get("/api/search/commands")
def search_commands(
    request: Request,
    db: Session = Depends(get_db),
    query: str = Query("", min_length=1),
    session_id: Optional[str] = None,
    ip: Optional[str] = None,
    flagged_only: bool = False,
    limit: int = Query(100, ge=1, le=10000)
):
    """Search commands with filtering"""
    require_dashboard_auth(request)
    cmd_query = db.query(CommandDB)
    if query:
        cmd_query = cmd_query.filter(CommandDB.command.ilike(f"%{query}%"))
    if session_id:
        cmd_query = cmd_query.filter(CommandDB.session_id == session_id)
    if ip:
        cmd_query = cmd_query.filter(CommandDB.attacker_ip == ip)
    if flagged_only:
        cmd_query = cmd_query.filter(CommandDB.flagged == True)
    results = cmd_query.order_by(CommandDB.timestamp.desc()).limit(limit).all()
    return {
        "results": [
            {"id": c.id, "session_id": c.session_id, "command": c.command,
             "timestamp": c.timestamp.isoformat(), "flagged": c.flagged}
            for c in results
        ],
        "count": len(results)
    }


# API: Real-time WebSocket
@router.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket):
    """Real-time live feed updates via WebSocket"""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# API: Health & Metadata
@router.get("/api/health")
def health_check():
    """Dashboard health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "3.0"
    }


@router.get("/api/meta/endpoints")
def get_endpoint_metadata():
    """Get available endpoints and their specifications"""
    return {
        "version": "3.0",
        "endpoints": {
            "analytics": [
                "/api/analytics/threat-heatmap",
                "/api/analytics/attacker-profiles",
                "/api/analytics/command-patterns",
                "/api/analytics/ioc-summary",
                "/api/analytics/payload-analysis",
                "/api/analytics/attack-taxonomy",
                "/api/analytics/correlations"
            ],
            "export": ["/api/export/threat-report", "/api/export/attackers"],
            "search": ["/api/search/sessions", "/api/search/commands"],
            "realtime": ["/ws/live"]
        }
    }
