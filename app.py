"""FastAPI entry point for honeypot framework"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import routers
from src.api.endpoints.attackers import router as attackers_router
from src.api.endpoints.sessions import router as sessions_router

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

@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}