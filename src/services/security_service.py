"""Security Hardening - RBAC, API Keys, Rate Limiting, Audit Logs"""
import os
import time
import hashlib
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta, timezone
from functools import wraps

# Try Redis for rate limiting
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


# API Keys storage (in production, use Vault or encrypted DB)
VALID_API_KEYS = set(os.getenv("API_KEYS", "").split(","))


class SecurityMiddleware:
    """
    Security controls for SOC platform:
    - Session-based RBAC
    - API key authentication
    - Rate limiting
    - Audit logging
    """
    
    RATE_LIMITS = {
        "default": (100, 60),  # 100 req/min
        "login": (5, 60),  # 5 attempts/min
        "api": (200, 60),  # 200 req/min for API
    }
    
    def __init__(self):
        if REDIS_AVAILABLE:
            self.redis = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=6379, db=1)
        else:
            self.redis = None
            self._local_limits = {}
    
    def rate_limit(self, key_prefix: str = "default"):
        """Rate limiting decorator"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Get request context
                request = kwargs.get('request')
                if not request:
                    return await func(*args, **kwargs)
                
                client_ip = request.client.host if request.client else "unknown"
                limit, window = self.RATE_LIMITS.get(key_prefix, self.RATE_LIMITS["default"])
                
                if self._check_rate_limit(f"{key_prefix}:{client_ip}", limit, window):
                    return await func(*args, **kwargs)
                
                from fastapi import HTTPException
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
            return wrapper
        return decorator
    
    def _check_rate_limit(self, key: str, limit: int, window: int) -> bool:
        """Check rate limit - Redis or local fallback"""
        if self.redis:
            try:
                current = self.redis.incr(key)
                if current == 1:
                    self.redis.expire(key, window)
                return current <= limit
            except:
                pass
        
        # Local fallback
        now = time.time()
        if key not in self._local_limits:
            self._local_limits[key] = []
        
        self._local_limits[key] = [t for t in self._local_limits[key] if now - t < window]
        self._local_limits[key].append(now)
        
        return len(self._local_limits[key]) <= limit
    
    def require_api_key(self, request) -> Optional[str]:
        """Validate API key from header"""
        api_key = request.headers.get("X-API-Key")
        if api_key and api_key in VALID_API_KEYS:
            return api_key
        return None


class AuditLogger:
    """Audit trail for SOC operations"""
    
    def __init__(self, db=None):
        self.db = db
    
    def log(self, action: str, user: str, ip: str, details: Dict = None):
        """Log audit event"""
        # In production, write to dedicated audit table
        print(f"[AUDIT] {datetime.now(timezone.utc).isoformat()} {user}@{ip} {action} {details}")
        
        if self.db:
            from src.core.database import AuditLogDB
            entry = AuditLogDB(
                user=user,
                ip=ip,
                action=action,
                details=details
            )
            self.db.add(entry)
            self.db.commit()


# Actions logged
AUDIT_ACTIONS = {
    "LOGIN": "user_login",
    "LOGOUT": "user_logout",
    "VIEW_SESSION": "view_session",
    "EXPORT_IOC": "export_ioc",
    "DOWNLOAD_PAYLOAD": "download_payload",
}