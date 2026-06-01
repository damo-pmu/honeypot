"""Dashboard endpoints - real-time monitoring with minimal auth"""
import os
import asyncio
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse
from pydantic import BaseModel
import json
from collections import Counter

# Import session auth
from ..middleware.session import (
    create_session, get_session, clear_session, require_auth,
    DASHBOARD_PASSWORD, LOGIN_HTML, _sessions
)
# Import audit logger
from ...utils.audit_logger import log_auth_event, log_dashboard_event

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

# In-memory event store (use Redis in production)
_dashboard_events = []
_event_counts = Counter()  # Track attack types


def add_event(event_type: str, data: dict):
    """Add event to dashboard stream"""
    event = {
        "type": event_type,
        "data": data,
        "timestamp": datetime.utcnow().isoformat()
    }
    _dashboard_events.append(event)
    _event_counts[event_type] += 1
    
    # Keep last 100 events
    if len(_dashboard_events) > 100:
        old_event = _dashboard_events.pop(0)
        _event_counts[old_event["type"]] -= 1
        if _event_counts[old_event["type"]] <= 0:
            del _event_counts[old_event["type"]]


def get_stats() -> dict:
    """Get dashboard statistics"""
    return {
        "total_events": len(_dashboard_events),
        "attack_types": dict(_event_counts.most_common(10)),
        "last_event": _dashboard_events[-1] if _dashboard_events else None
    }


@router.get("/")
def dashboard_home(request: Request):
    """Serve dashboard HTML - redirect to login if no session"""
    if get_session(request):
        return HTMLResponse(_get_dashboard_html())
    return HTMLResponse(LOGIN_HTML)


def _get_dashboard_html():
    """Dashboard HTML after login - Pro features"""
    return """
<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    <link rel="stylesheet" href="https://unpkg.com/@picocss/pico@latest/css/pico.min.css">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        body { background: #0a0a0a; color: #e0e0e0; }
        .live-indicator { 
            display: inline-block; width: 10px; height: 10px; 
            background: #00ff88; border-radius: 50%; 
            animation: pulse 2s infinite;
        }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        .event-card { 
            background: #111; border: 1px solid #333; 
            border-radius: 8px; padding: 16px; margin: 8px 0;
        }
        .event-time { color: #888; font-size: 0.85em; }
        .event-type { 
            display: inline-block; padding: 2px 8px; 
            background: #00aaff; color: #000; border-radius: 4px; 
            font-weight: bold; font-size: 0.8em;
        }
        .stat-card { 
            background: #1a1a1a; border: 1px solid #333; 
            border-radius: 8px; padding: 16px; text-align: center;
        }
        .stat-value { color: #00ff88; font-size: 2em; font-weight: bold; }
        .stat-label { color: #888; font-size: 0.9em; }
        #map { height: 300px; border-radius: 8px; margin-top: 16px; }
        .filter-btn { 
            margin: 4px; font-size: 0.85em;
        }
        .filter-btn.active { background: #00ff88; color: #000; }
    </style>
</head>
<body>
    <nav style="padding: 1rem; border-bottom: 1px solid #333;">
        <div class="container-fluid">
            <strong style="color: #00ff88;">🍯 Honeypot Dashboard</strong>
            <span class="live-indicator"></span> Live
            <a href="/dashboard/stats" class="secondary filter-btn">Stats</a>
            <a href="/logout" role="button" class="secondary">Logout</a>
        </div>
    </nav>
    
    <main class="container">
        <!-- Stats Row -->
        <section id="stats" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin: 16px 0;">
            <div class="stat-card">
                <div class="stat-value" id="total-events">-</div>
                <div class="stat-label">Total Events</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="attack-count">-</div>
                <div class="stat-label">Attacks (24h)</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="unique-ips">-</div>
                <div class="stat-label">Unique IPs</div>
            </div>
        </section>
        
        <!-- World Map -->
        <div id="map"></div>
        
        <!-- Filters -->
        <section style="margin: 16px 0;">
            <small>Filter by type:</small>
            <div id="filters">
                <a href="#" class="secondary filter-btn active" data-filter="all">All</a>
                <a href="#" class="secondary filter-btn" data-filter="ssh_login">SSH Login</a>
                <a href="#" class="secondary filter-btn" data-filter="telnet">Telnet</a>
                <a href="#" class="secondary filter-btn" data-filter="command">Command</a>
            </div>
        </section>
        
        <!-- Events List -->
        <div id="events" class="flow">
            Loading events...
        </div>
    </main>
    
    <script>
        // Stats loading
        fetch('/dashboard/stats')
            .then(r => r.json())
            .then(data => {
                document.getElementById('total-events').textContent = data.total_events;
                document.getElementById('attack-count').textContent = Object.values(data.attack_types)
                    .reduce((a, b) => a + b, 0);
            });
        
        // Leaflet map avec géolocalisation
        const map = L.map('map').setView([20, 0], 2);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: 'Honeypot'
        }).addTo(map);
        const markers = {};
        
        async function geolocateIP(ip) {
            if (markers[ip]) return markers[ip];
            const resp = await fetch(`https://ipapi.co/${ip}/json/`);
            const data = await resp.json();
            const latlng = [data.lat, data.lon];
            if (latlng[0] && latlng[1]) {
                const marker = L.marker(latlng).addTo(map)
                    .bindPopup(`<b>${ip}</b><br>${data.city || ''}, ${data.country_name || ''}`);
                markers[ip] = marker;
                map.setView(latlng, 5);
                return marker;
            }
        }
        
        // SSE stream
        const evtSource = new EventSource('/dashboard/stream');
        const eventsDiv = document.getElementById('events');
        const seenIps = new Set();
        
        evtSource.onmessage = e => {
            const event = JSON.parse(e.data);
            addEvent(event);
        };
        
        evtSource.onerror = () => {
            // Reconnect after 3s on error
            setTimeout(() => {
                evtSource.close();
                new EventSource('/dashboard/stream');
            }, 3000);
        };
        
        function addEvent(event) {
            // Track unique IPs + geolocate
            if (event.data.ip) {
                seenIps.add(event.data.ip);
                if (!markers[event.data.ip] && event.data.ip) {
                    geolocateIP(event.data.ip);
                }
            }
            
            
            const div = document.createElement('div');
            div.className = 'event-card';
            div.innerHTML = `
                <small class="event-time">${event.timestamp}</small>
                <span class="event-type">${event.type}</span>
                <pre>${JSON.stringify(event.data, null, 2)}</pre>
            `;
            eventsDiv.prepend(div);
            
            // Update counters
            document.getElementById('total-events').textContent = 
                parseInt(document.getElementById('total-events').textContent || 0) + 1;
            document.getElementById('unique-ips').textContent = seenIps.size;
        }
    </script>
</body>
</html>
"""


@router.get("/stats")
def get_dashboard_stats(session: str = Depends(require_auth)):
    """Get dashboard statistics"""
    return get_stats()


@router.post("/login")
async def login(request: Request, response: Response):
    """Login with password form - returns dashboard HTML with session cookie"""
    form = await request.form()
    password = form.get("password", "")
    client_ip = request.client.host if request.client else "unknown"
    
    if password == DASHBOARD_PASSWORD:
        session = create_session(response)
        log_auth_event("login", True, client_ip, {"method": "form"})
        
        # Build response with both cookie and HTML body
        html_content = _get_dashboard_html()
        return HTMLResponse(content=html_content,
            headers={"Set-Cookie": f"dash_session={session}; HttpOnly; Path=/; SameSite=strict"}
        )
    
    log_auth_event("login_failed", False, client_ip, {"reason": "invalid_password"})
    return HTMLResponse(LOGIN_HTML + "<p style='color:red'>Invalid password</p>")


@router.get("/logout")
def logout(request: Request, response: Response):
    """Logout and clear session"""
    session = get_session(request)
    client_ip = request.client.host if request.client else "unknown"
    
    if session:
        clear_session(response, session)
        log_auth_event("logout", True, client_ip, {})
    
    return RedirectResponse("/dashboard/", status_code=303)


@router.get("/stream")
async def stream(request: Request, session: str = Depends(require_auth)):
    """Server-sent events stream - requires session"""
    
    async def event_generator():
        # Send existing events
        for event in _dashboard_events[-20:]:
            yield f"data: {json.dumps(event)}\n\n"
        
        # Stream new events
        last_id = len(_dashboard_events)
        while True:
            if await request.is_disconnected():
                break
            
            # Send new events
            while last_id < len(_dashboard_events):
                yield f"data: {json.dumps(_dashboard_events[last_id])}\n\n"
                last_id += 1
            
            await asyncio.sleep(0.5)
    
    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/events/recent")
def get_recent_events(session: str = Depends(require_auth), limit: int = 20):
    """Get recent events - requires session"""
    return _dashboard_events[-limit:]


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