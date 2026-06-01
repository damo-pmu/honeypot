"""Session auth middleware for dashboard - cookie-based login"""
import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Request, Response, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse

# Session store (use Redis in production)
_sessions: dict = {}

DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASS", "change-me-in-prod")
SESSION_DURATION_HOURS = 24


def create_session(response: Response) -> str:
    """Create a session and set cookie"""
    session_id = f"dash_{datetime.utcnow().timestamp()}_{os.urandom(4).hex()}"
    _sessions[session_id] = datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS)
    
    # Note: secure=False for dev, True in production (HTTPS)
    secure = os.getenv("HTTPS", "false").lower() == "true"
    
    response.set_cookie(
        key="dash_session",
        value=session_id,
        httponly=True,
        samesite="strict",
        secure=secure
    )
    return session_id


def get_session(request: Request) -> Optional[str]:
    """Get valid session from cookie"""
    session_id = request.cookies.get("dash_session")
    if session_id and session_id in _sessions:
        if _sessions[session_id] > datetime.utcnow():
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


LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard Login - Honeypot</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
            color: #e0e0e0;
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            background: #111;
            border: 1px solid #333;
            border-radius: 12px;
            padding: 32px;
            width: 320px;
            box-shadow: 0 10px 40px rgba(0, 255, 136, 0.1);
        }
        h1 { color: #00ff88; text-align: center; margin-bottom: 24px; }
        input {
            width: 100%;
            padding: 12px;
            margin: 12px 0;
            background: #000;
            border: 1px solid #333;
            border-radius: 6px;
            color: #00ff88;
            font-size: 14px;
        }
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(90deg, #00ff88, #00aaff);
            border: none;
            border-radius: 6px;
            color: #000;
            font-weight: bold;
            cursor: pointer;
            margin-top: 16px;
        }
        .error { color: #ff4444; font-size: 12px; margin-top: 8px; }
    </style>
</head>
<body>
    <div class="login-card">
        <h1>🍯 Honeypot Dashboard</h1>
        <form method="POST" action="/login">
            <input name="password" type="password" placeholder="Mot de passe" required>
            <button type="submit">Se connecter</button>
            <div class="error" id="error"></div>
        </form>
    </div>
    <script>
        const url = new URL(location);
        if (url.searchParams.get('error')) {
            document.getElementById('error').textContent = 'Invalid password';
        }
    </script>
</body>
</html>
"""