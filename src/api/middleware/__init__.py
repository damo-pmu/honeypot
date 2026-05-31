"""API middleware - auth, audit logging"""
from .audit import AuditMiddleware
from .session import create_session, get_session, clear_session, require_auth