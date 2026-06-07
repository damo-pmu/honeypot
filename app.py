"""FastAPI entry point for honeypot framework"""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Import routers
from src.api.endpoints.attackers import router as attackers_router
from src.api.endpoints.sessions import router as sessions_router
from src.api.endpoints.commands import router as commands_router
from src.api.endpoints.behavior import router as behavior_router
from src.api.endpoints.analytics import router as analytics_router
from src.api.endpoints.enrichment import router as enrichment_router
from src.api.endpoints.ioc import router as ioc_router
from src.api.endpoints.response import router as response_router
from src.api.endpoints.dashboard_v3 import router as dashboard_v3_router
from src.api.endpoints.attacks import router as attacks_router

# Import audit middleware
from src.api.middleware.audit import AuditMiddleware
from src.infrastructure.observability.metrics import metrics_endpoint

# Import database
from src.core.database import init_db

app = FastAPI(
    title="Honeypot Threat Intelligence API",
    version="0.1.0"
)

# CORS configuration (restricted to configured origins for security)
# For development: Use HONEYPOT_HOSTNAME and CORS_ALLOWED_ORIGINS to avoid hardcoding
honeypot_hostname = os.getenv("HONEYPOT_HOSTNAME", "localhost")
configured_origins = os.getenv("CORS_ALLOWED_ORIGINS")
if configured_origins:
    allowed_origins = [origin.strip() for origin in configured_origins.split(",") if origin.strip()]
else:
    allowed_origins = [
        f"http://{honeypot_hostname}:3000",
        f"http://{honeypot_hostname}:5000",
        f"http://{honeypot_hostname}:9090",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
    allow_credentials=True,
)

# Audit logging middleware
app.add_middleware(AuditMiddleware)

# Static files mount for dashboard assets
app.mount("/static", StaticFiles(directory="static"), name="static")

# Include routers
app.include_router(attackers_router)
app.include_router(sessions_router)
app.include_router(commands_router)
app.include_router(behavior_router)
app.include_router(analytics_router)
app.include_router(enrichment_router)
app.include_router(ioc_router)
app.include_router(response_router)
app.include_router(dashboard_v3_router)
app.include_router(attacks_router)


@app.on_event("startup")
async def startup_event():
    """Initialize database on app startup"""
    init_db()


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}


@app.get("/metrics")
def metrics():
    return metrics_endpoint()