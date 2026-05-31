"""Structured audit logging for honeypot operations
JSON format for easy parsing and analysis
"""
import json
import logging
from datetime import datetime
from typing import Optional
from pathlib import Path
import os

# Configure audit log path
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "/tmp/honeypot_audit.log")

# Custom formatter for JSON logs
class AuditFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, 'extra_data'):
            log_entry["data"] = record.extra_data
        return json.dumps(log_entry)


def get_audit_logger(name: str = "honeypot.audit") -> logging.Logger:
    """Get configured audit logger"""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(AuditFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


# Event-specific loggers
audit = get_audit_logger()
auth_audit = get_audit_logger("honeypot.auth")
event_audit = get_audit_logger("honeypot.events")


def log_auth_event(action: str, success: bool, ip: str, details: dict = None):
    """Log authentication events"""
    auth_audit.info(
        f"Auth {action} {'success' if success else 'failed'} from {ip}",
        extra={"extra_data": {
            "action": action,
            "success": success,
            "ip": ip,
            "details": details or {}
        }}
    )


def log_dashboard_event(event_type: str, ip: str, session: str = None, data: dict = None):
    """Log dashboard interactions (login, event view)"""
    audit.info(
        f"Dashboard {event_type}",
        extra={"extra_data": {
            "event_type": event_type,
            "ip": ip,
            "session": session,
            "data": data or {}
        }}
    )


def log_attack_event(attack_type: str, ip: str, session_id: str = None, payload: dict = None):
    """Log attack events from honeypot"""
    event_audit.info(
        f"Attack {attack_type} from {ip}",
        extra={"extra_data": {
            "attack_type": attack_type,
            "source_ip": ip,
            "session_id": session_id,
            "payload": payload or {}
        }}
    )


def log_worker_event(action: str, status: str, details: dict = None):
    """Log worker operations"""
    audit.info(
        f"Worker {action} status={status}",
        extra={"extra_data": {
            "action": action,
            "status": status,
            "details": details or {}
        }}
    )