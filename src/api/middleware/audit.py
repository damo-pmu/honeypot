"""FastAPI middleware for request/operation logging"""
import time
from datetime import datetime
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import json

from ...utils.audit_logger import get_audit_logger

api_logger = get_audit_logger("honeypot.api")


class AuditMiddleware(BaseHTTPMiddleware):
    """Log all API requests and responses for debugging"""
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # Log incoming request
        api_logger.info(
            f"Incoming {request.method} {request.url.path}",
            extra={"extra_data": {
                "method": request.method,
                "path": request.url.path,
                "query": dict(request.query_params),
                "client_ip": request.client.host if request.client else "unknown",
                "user_agent": request.headers.get("user-agent", "")[:100]
            }}
        )
        
        try:
            response = await call_next(request)
            duration = time.time() - start_time
            
            # Log response
            api_logger.info(
                f"Response {request.method} {request.url.path}: {response.status_code}",
                extra={"extra_data": {
                    "status": response.status_code,
                    "duration_ms": round(duration * 1000, 2),
                    "path": request.url.path
                }}
            )
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            
            api_logger.error(
                f"Error in {request.method} {request.url.path}: {str(e)}",
                extra={"extra_data": {
                    "error": type(e).__name__,
                    "message": str(e),
                    "duration_ms": round(duration * 1000, 2),
                    "path": request.url.path
                }}
            )
            raise