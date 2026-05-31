"""Dashboard endpoints - real-time monitoring with minimal auth"""
import os
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
import json

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

# Simple auth token (set in .env)
DASHBOARD_TOKEN = os.getenv("DASHBOARD_TOKEN", "change-me-in-prod")


def verify_token(request: Request):
    """Verify dashboard token from header or cookie"""
    token = request.headers.get("X-Dashboard-Token") or request.cookies.get("dash_token")
    if token != DASHBOARD_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid or missing token")
    return token


class LoginRequest(BaseModel):
    token: str


# In-memory event store (use Redis in production)
_dashboard_events = []


def add_event(event_type: str, data: dict):
    """Add event to dashboard stream"""
    event = {
        "type": event_type,
        "data": data,
        "timestamp": datetime.utcnow().isoformat()
    }
    _dashboard_events.append(event)
    # Keep last 100 events
    if len(_dashboard_events) > 100:
        _dashboard_events.pop(0)


@router.get("/")
def dashboard_home():
    """Serve dashboard HTML"""
    html = """
<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Dashboard</title>
    <meta charset="utf-8">
    <style>
        body { font-family: monospace; background: #0a0a0a; color: #00ff88; padding: 20px; }
        .event { border-bottom: 1px solid #333; padding: 8px; margin: 4px 0; }
        .event-time { color: #888; font-size: 0.9em; }
        .event-type { color: #00aaff; font-weight: bold; }
        #events { max-height: 80vh; overflow-y: auto; }
        input, button { background: #111; color: #00ff88; border: 1px solid #00ff88; padding: 8px; }
        input { width: 300px; }
    </style>
</head>
<body>
    <h1>🍯 Honeypot Dashboard</h1>
    <div id="auth">
        <input id="token" placeholder="Enter dashboard token" type="password">
        <button onclick="connect()">Connect</button>
    </div>
    <div id="events" style="display:none;"></div>
    <script>
        let token = localStorage.getItem('dash_token');
        if (token) { connect(); }
        
        function connect() {
            token = document.getElementById('token').value;
            localStorage.setItem('dash_token', token);
            document.getElementById('auth').style.display = 'none';
            document.getElementById('events').style.display = 'block';
            const evtSource = new EventSource('/dashboard/stream');
            evtSource.onmessage = e => {
                const event = JSON.parse(e.data);
                addEvent(event);
            };
        }
        
        function addEvent(event) {
            const div = document.createElement('div');
            div.className = 'event';
            div.innerHTML = `<span class="event-time">${event.timestamp}</span>
                <span class="event-type">[${event.type}]</span> ${JSON.stringify(event.data)}`;
            document.getElementById('events').prepend(div);
        }
    </script>
</body>
</html>
"""
    return HTMLResponse(html)


@router.post("/login")
def login(request: LoginRequest, response: Response):
    """Login and get cookie"""
    if request.token == DASHBOARD_TOKEN:
        response.set_cookie(key="dash_token", value=request.token, httponly=True)
        return {"status": "ok"}
    raise HTTPException(status_code=401, detail="Invalid token")


@router.get("/stream")
async def stream(request: Request, token: str = Depends(verify_token)):
    """Server-sent events stream"""
    
    async def event_generator():
        # Send existing events
        for event in _dashboard_events[-20:]:
            yield f"data: {json.dumps(event)}\n\n"
        
        # Stream new events
        last_id = len(_dashboard_events)
        while True:
            # Check if client disconnected
            if await request.is_disconnected():
                break
            
            # Send new events
            while last_id < len(_dashboard_events):
                yield f"data: {json.dumps(_dashboard_events[last_id])}\n\n"
                last_id += 1
            
            await request.body()  # Small delay
    
    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/events/recent")
def get_recent_events(token: str = Depends(verify_token), limit: int = 50):
    """Get recent events"""
    return _dashboard_events[-limit:]


@router.post("/event")
def emit_event(event_type: str, data: dict, token: str = Depends(verify_token)):
    """Emit event to all connected clients (called by worker)"""
    add_event(event_type, data)
    return {"status": "emitted"}


class EventRequest(BaseModel):
    event_type: str
    data: dict


@router.post("/emit")
def emit_event_json(request: EventRequest):
    """Emit event via JSON body (no auth for internal worker)"""
    add_event(request.event_type, request.data)
    return {"status": "emitted"}