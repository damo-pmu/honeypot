# Dashboard Authentication Plan - Phase 3

## Current State (2026-06-07)

### Implémenté ✅
- `DASHBOARD_PASS` via `.env` (middleware/session.py:10)
- Cookie `dash_session` HttpOnly, SameSite=Strict, 24h expiration
- `require_dashboard_auth` dépendance (dashboard_v3.py:59-64)
- Routes API protégées : `/api/analytics/*`, `/api/export/*`, `/api/search/*`

### Manquant ❌
- Routes UI NON protégées : `/dashboard/`, `/dashboard/analytics`, `/dashboard/settings`
- Pas de `/dashboard/login` UI endpoint
- Pas de `/dashboard/logout` endpoint
- Session store en mémoire (pas de Redis)

## Implementation Plan

### Phase 1: Protect UI Routes
```python
# src/api/endpoints/dashboard_v3.py
@router.get("/", response_class=HTMLResponse)
def dashboard_home(request: Request, db: Session = Depends(get_db), _: bool = Depends(require_dashboard_auth)):
    # Add auth check
```

### Phase 2: Add Login/Logout UI Endpoints
```python
@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    # Render login.html template

@router.post("/login")
def login_submit(request: Request, password: str = Form(...)):
    # Validate against DASHBOARD_PASS
    # Create session, redirect to /dashboard/

@router.get("/logout")
def logout(request: Request):
    # Clear session, redirect to /login
```

### Phase 3: Redis Session Store (Production)
```python
# Replace _sessions dict with Redis
redis_client = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))
```

### Phase 4: Tests Required
- [ ] UI routes redirect to login when unauthenticated
- [ ] Login with correct password creates session
- [ ] Login with wrong password rejects
- [ ] Logout clears session
- [ ] Session expires after 24h

## Security Notes
- HttpOnly + SameSite=Strict empêche CSRF
- Secure cookie doit être True en production (HTTPS)
- Redis doit être configuré pour les déploiements multi-instance