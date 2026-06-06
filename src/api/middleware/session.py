"""Session auth middleware for dashboard - cookie-based login"""
import os
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import Request, Response, HTTPException, Depends

# Session store (use Redis in production)
_sessions: dict = {}

DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASS", "change-me-in-prod")
SESSION_DURATION_HOURS = 24


def create_session(response: Response) -> str:
    """Create a session and set cookie"""
    session_id = f"dash_{datetime.now(timezone.utc).timestamp()}_{os.urandom(4).hex()}"
    _sessions[session_id] = datetime.now(timezone.utc) + timedelta(hours=SESSION_DURATION_HOURS)
    
    # Note: secure=False for dev, True in production (HTTPS)
    secure = os.getenv("HTTPS", "false").lower() == "true"
    max_age = SESSION_DURATION_HOURS * 3600
    
    response.set_cookie(
        key="dash_session",
        value=session_id,
        httponly=True,
        samesite="strict",
        secure=secure,
        max_age=max_age,
        expires=max_age,
        path="/"
    )
    return session_id


def get_session(request: Request) -> Optional[str]:
    """Get valid session from cookie"""
    session_id = request.cookies.get("dash_session")
    if session_id and session_id in _sessions:
        if _sessions[session_id] > datetime.now(timezone.utc):
            return session_id
        del _sessions[session_id]
    return None


def validate_session_id(session_id: str) -> Optional[str]:
    """Validate a raw session id for non-HTTP access"""
    if not session_id:
        return None
    if session_id in _sessions:
        if _sessions[session_id] > datetime.now(timezone.utc):
            return session_id
        del _sessions[session_id]
    return None


def clear_session(response: Response, session_id: str):
    """Invalidate session"""
    _sessions.pop(session_id, None)
    response.delete_cookie("dash_session")


async def require_auth(request: Request):
    """Dependency that raises if no valid session"""
    session = get_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Authentication required")
    return session
