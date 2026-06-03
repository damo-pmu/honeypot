"""Dashboard endpoints - Refactored for SOC architecture with DB as single source of truth"""
import json
import asyncio
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel

# Templates setup
from jinja2 import Environment, FileSystemLoader, select_autoescape

jinja_env = Environment(
    loader=FileSystemLoader("/app/src/templates"),
    autoescape=select_autoescape(["html", "xml"]),
)
jinja_env.bytecode_cache = None


def render_template(template_name: str, context: dict, status_code: int = 200, headers: dict = None) -> HTMLResponse:
    """Render Jinja2 template directly without cache issues."""
    tmpl = jinja_env.get_template(template_name)
    html = tmpl.render(**context)
    return HTMLResponse(html, status_code=status_code, headers=headers)


# Session auth
from src.api.middleware.session import (
    create_session, get_session, clear_session, DASHBOARD_PASSWORD
)
from src.utils.audit_logger import log_auth_event

# Database
from src.core.database import get_db, AttackDB

# Services
from src.services.statistics_service import StatisticsService
from src.services.event_bus import event_bus, Event

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


# ============================================================
# UI Routes (templated)
# ============================================================
@router.get("/")
def dashboard_home(request: Request, db: Session = Depends(get_db)):
    """Serve dashboard HTML - initial load fetches all data via API"""
    if get_session(request):
        service = StatisticsService(db)
        stats = service.get_dashboard_stats()
        return render_template("dashboard.html", {"request": request, "stats": stats})
    return render_template("login.html", {"request": request, "error": None})


@router.post("/login")
async def login(request: Request, response: Response, db: Session = Depends(get_db)):
    """Login with password form"""
    form = await request.form()
    password = form.get("password", "")
    client_ip = request.client.host if request.client else "unknown"
    
    if password == DASHBOARD_PASSWORD:
        session = create_session(response)
        log_auth_event("login", True, client_ip, {"method": "form"})
        
        # Get stats for initial render
        service = StatisticsService(db)
        stats = service.get_dashboard_stats()
        
        return render_template(
            "dashboard.html",
            {"request": request, "stats": stats},
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
# API Routes (JSON) - All data from PostgreSQL
# ============================================================
@router.get("/api/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Get dashboard statistics - SINGLE SOURCE OF TRUTH: PostgreSQL"""
    service = StatisticsService(db)
    return service.get_dashboard_stats()


@router.get("/api/live-feed")
def get_live_feed(db: Session = Depends(get_db), limit: int = 50):
    """Get recent events for live feed - from DB, ordered by timestamp desc"""
    service = StatisticsService(db)
    return {"items": service.get_live_feed(limit=limit)}


@router.get("/api/sessions")
def get_sessions(
    db: Session = Depends(get_db),
    protocol: Optional[str] = None,
    ip: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    """Get sessions list with optional filtering"""
    from src.repositories.session_repository import SessionRepository
    repo = SessionRepository(db)
    return repo.get_list(protocol=protocol, ip=ip, limit=limit, offset=offset)


@router.get("/api/sessions/{session_id}")
def get_session_detail(session_id: str, db: Session = Depends(get_db)):
    """Get full session aggregation for investigation panel"""
    from src.repositories.session_repository import SessionRepository
    repo = SessionRepository(db)
    result = repo.get_full_detail(session_id)
    if not result:
        raise HTTPException(status_code=404, detail="Session not found")
    return result


@router.get("/api/timeline/{session_id}")
def get_session_timeline(session_id: str, db: Session = Depends(get_db)):
    """Get structured attack timeline for investigation"""
    from src.repositories.attack_repository import AttackRepository
    from src.services.timeline_builder import TimelineBuilder
    
    repo = AttackRepository(db)
    events = repo.get_by_session(session_id)
    
    if not events:
        return {"timeline": [], "story": "No events found"}
    
    builder = TimelineBuilder(session_id, events)
    return builder.get_story()


@router.get("/api/replay/{session_id}")
def get_session_replay(session_id: str, db: Session = Depends(get_db)):
    """Get chronological session replay for investigation"""
    from src.services.replay_service import ReplayService
    
    service = ReplayService(session_id, db)
    return service.get_replay()


@router.get("/api/mitre/{session_id}")
def get_mitre_mapping(session_id: str, db: Session = Depends(get_db)):
    """Get MITRE ATT&CK mapping for all events in session"""
    from src.repositories.attack_repository import AttackRepository
    from src.services.mitre_mapper import MitreMapper
    
    repo = AttackRepository(db)
    events = repo.get_by_session(session_id)
    
    all_mappings = []
    for event in events:
        mapper = MitreMapper(event)
        mappings = mapper.map()
        all_mappings.extend(mappings)
    
    return {"mappings": all_mappings, "session_id": session_id}


@router.get("/api/iocs")
def get_all_iocs(
    db: Session = Depends(get_db),
    limit: int = 100,
    ioc_type: Optional[str] = None
):
    """Get extracted IOCs - optionally filtered by type"""
    from src.core.database import IOCDb
    
    query = db.query(IOCDb)
    if ioc_type:
        query = query.filter(IOCDb.ioc_type == ioc_type)
    
    iocs = query.order_by(IOCDb.first_seen.desc()).limit(limit).all()
    
    return {
        "items": [
            {
                "id": i.id,
                "ioc_type": i.ioc_type,
                "value": i.value,
                "confidence": i.confidence,
                "source": i.source,
                "first_seen": i.first_seen.isoformat() if i.first_seen else None
            }
            for i in iocs
        ],
        "count": len(iocs)
    }


@router.post("/api/iocs/extract/{session_id}")
def extract_iocs_session(session_id: str, db: Session = Depends(get_db)):
    """Extract IOCs from session events on-demand"""
    from src.repositories.attack_repository import AttackRepository
    from src.services.ioc_extractor import IOCService
    
    repo = AttackRepository(db)
    events = repo.get_by_session(session_id)
    
    service = IOCService(db)
    iocs = service.extract_from_session(session_id, events)
    
    return {
        "iocs": [{"value": i.value, "type": i.ioc_type, "context": i.context} for i in iocs],
        "session_id": session_id,
        "count": len(iocs)
    }


@router.get("/api/payloads")
def get_payloads(
    db: Session = Depends(get_db),
    limit: int = 50,
    suspicious_only: bool = False
):
    """Get analyzed payloads - from DB records"""
    from src.core.database import PayloadDB
    
    query = db.query(PayloadDB)
    if suspicious_only:
        query = query.filter(PayloadDB.packed == True)
    
    payloads = query.order_by(PayloadDB.first_seen.desc()).limit(limit).all()
    
    return {
        "items": [
            {
                "id": p.id,
                "sha256": p.sha256,
                "md5": p.md5,
                "size": p.size,
                "entropy": p.entropy,
                "file_type": p.file_type,
                "suspicious": p.suspicious,
                "packed": p.packed,
                "first_seen": p.first_seen.isoformat() if p.first_seen else None
            }
            for p in payloads
        ],
        "count": len(payloads)
    }


@router.get("/api/payloads/{sha256}")
def get_payload_detail(sha256: str, db: Session = Depends(get_db)):
    """Get specific payload analysis"""
    from src.core.database import PayloadDB
    
    payload = db.query(PayloadDB).filter(PayloadDB.sha256 == sha256).first()
    if not payload:
        raise HTTPException(status_code=404, detail="Payload not found")
    
    return {
        "sha256": payload.sha256,
        "md5": payload.md5,
        "size": payload.size,
        "entropy": payload.entropy,
        "file_type": payload.file_type,
        "strings": payload.strings,
        "suspicious": payload.suspicious,
        "packed": payload.packed,
        "analysis": payload.analysis
    }


@router.get("/api/behavior/{session_id}")
def get_behavior_analysis(session_id: str, db: Session = Depends(get_db)):
    """Analyze if attacker is human or bot"""
    from src.repositories.attack_repository import AttackRepository
    from src.services.behavior_analyzer import BehaviorAnalyzer
    
    repo = AttackRepository(db)
    events = repo.get_by_session(session_id)
    
    analyzer = BehaviorAnalyzer(session_id, events)
    return analyzer.analyze()


@router.get("/api/graph/{session_id}")
def get_investigation_graph(session_id: str, db: Session = Depends(get_db)):
    """Get full investigation graph for a session"""
    from src.services.graph_builder import GraphBuilder
    
    builder = GraphBuilder(db)
    return builder.build_for_session(session_id)


@router.get("/api/campaigns")
def get_campaigns(
    db: Session = Depends(get_db),
    hours: int = 24,
    limit: int = 20
):
    """Get detected attack campaigns"""
    from src.services.campaign_engine import CampaignEngine
    
    engine = CampaignEngine(db)
    return {"campaigns": engine.detect_campaigns(hours=hours)[:limit]}


@router.get("/api/map")
def get_map_data(db: Session = Depends(get_db)):
    """Get geoip markers for map - already enriched in DB"""
    service = StatisticsService(db)
    return service.get_geoip_markers(limit=100)


@router.get("/api/events/history")
def get_events_history(
    db: Session = Depends(get_db), 
    limit: int = 50,
    offset: int = 0,
    event_type: Optional[str] = None,
    hours: int = 24
):
    """Get paginated event history - separate from live feed"""
    from src.repositories.attack_repository import AttackRepository
    repo = AttackRepository(db)
    
    # Get attacks with limit/offset
    attacks = db.query(AttackDB).order_by(
        AttackDB.timestamp.desc()
    ).offset(offset).limit(limit).all()
    
    events = []
    for a in attacks:
        events.append({
            "type": "attack",
            "id": a.id,
            "timestamp": a.timestamp.isoformat(),
            "data": {
                "attack_type": a.attack_type,
                "protocol": a.protocol,
                "attacker_ip": a.attacker_ip,
                "severity": a.severity,
                "payload": a.payload[:200] if a.payload else None
            }
        })
    
    return {"items": events, "count": len(events)}


# ============================================================
# SSE - NOTIFICATIONS ONLY (no data payloads)
# ============================================================
# Async queue for SSE distribution
_sse_queue = None


@router.get("/stream")
async def stream(request: Request, session: Optional[str] = Depends(get_session)):
    """
    Server-sent events stream - sends ONLY notifications.
    
    Frontend must call specific APIs on notification:
    - attack_created → loadLiveFeed(), loadStats()
    - session_created → loadSessions(), loadStats()
    """
    global _sse_queue
    if _sse_queue is None:
        import asyncio
        _sse_queue = asyncio.Queue()
        event_bus.set_queue(_sse_queue)
    
    async def event_generator():
        yield f'data: {json.dumps({"type": "connected", "timestamp": datetime.utcnow().isoformat()})}\n\n'
        
        while True:
            if await request.is_disconnected():
                break
            try:
                event = await _sse_queue.get()
                yield f'data: {json.dumps({"type": event.type, "event_id": event.event_id, "timestamp": event.timestamp, "reference_id": event.reference_id, "session_id": event.session_id})}\n\n'
            except Exception:
                await asyncio.sleep(0.5)
            await asyncio.sleep(0.1)
    
    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/metrics")
def prometheus_metrics():
    """Prometheus metrics endpoint"""
    from src.services.observability_service import observability
    metrics = observability.get_metrics()
    if metrics:
        from fastapi import Response
        return Response(content=metrics, media_type="text/plain")
    return {"status": "prometheus not configured"}


# ============================================================
# Internal API (no auth) - for worker ingestion
# ============================================================
class EventRequest(BaseModel):
    session_id: str
    attacker_ip: str
    protocol: str
    attack_type: str
    payload: Optional[str] = None
    severity: int = 0


@router.post("/internal/events")
def ingest_attack_event(request: EventRequest, db: Session = Depends(get_db)):
    """
    Ingest attack event from worker - stores to DB then publishes notification.
    Called by cowrie_ingest worker.
    """
    from src.repositories.attack_repository import AttackRepository
    
    # Store in DB (single source of truth)
    repo = AttackRepository(db)
    attack = repo.create(
        session_id=request.session_id,
        attacker_ip=request.attacker_ip,
        protocol=request.protocol,
        attack_type=request.attack_type,
        payload=request.payload,
        severity=request.severity
    )
    
    # Publish notification via event bus
    event_bus.publish(
        event_type="attack_created",
        reference_id=str(attack.id),
        session_id=request.session_id
    )
    
    return {"status": "stored", "attack_id": attack.id}


class SessionEventRequest(BaseModel):
    session_id: str
    attacker_ip: str
    protocol: str


@router.post("/internal/sessions")
def upsert_session(request: SessionEventRequest, db: Session = Depends(get_db)):
    """Create or update session - called by worker on session start"""
    from src.repositories.session_repository import SessionRepository
    
    repo = SessionRepository(db)
    existing = repo.get_by_id(request.session_id)
    
    if existing:
        return {"status": "exists", "session_id": request.session_id}
    
    session = repo.create(
        session_id=request.session_id,
        attacker_ip=request.attacker_ip,
        protocol=request.protocol
    )
    
    event_bus.publish(
        event_type="session_created",
        session_id=request.session_id
    )
    
    return {"status": "created", "session_id": session.id}


@router.post("/internal/sessions/{session_id}/end")
def end_session(session_id: str, db: Session = Depends(get_db)):
    """Mark session as ended - called by worker on disconnect"""
    from src.repositories.session_repository import SessionRepository
    
    repo = SessionRepository(db)
    repo.update_end(session_id)
    
    event_bus.publish(
        event_type="session_ended",
        session_id=session_id
    )
    
    return {"status": "ended", "session_id": session_id}