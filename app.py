"""FastAPI entry point for honeypot framework"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import routers
from src.api.endpoints.attackers import router as attackers_router
from src.api.endpoints.sessions import router as sessions_router
from src.api.endpoints.commands import router as commands_router
from src.api.endpoints.behavior import router as behavior_router
from src.api.endpoints.analytics import router as analytics_router
from src.api.endpoints.enrichment import router as enrichment_router

app = FastAPI(
    title="Honeypot Threat Intelligence API",
    version="0.1.0"
)

# CORS for Grafana
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(attackers_router)
app.include_router(sessions_router)
app.include_router(commands_router)
app.include_router(behavior_router)
app.include_router(analytics_router)
app.include_router(enrichment_router)

@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}