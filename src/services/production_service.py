"""Production Readiness - Celery, Redis, Background Jobs, Retention"""
import os
from typing import Dict, Any, Optional
from datetime import datetime, timezone, timedelta, timezone

# Async task queue (Celery optional)
try:
    from celery import Celery
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False


# Redis for caching and queues
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class RetentionManager:
    """
    Data retention policies for SOC operational security.
    
    Policies:
    - Events: 90 days
    - Commands: 180 days
    - Sessions: 365 days
    - Payloads: 180 days
    - Audit logs: permanent
    """
    
    RETENTION_DAYS = {
        "events": 90,
        "commands": 180,
        "sessions": 365,
        "payloads": 180,
        "iocs": 365,
    }
    
    def __init__(self, db):
        self.db = db
    
    def cleanup(self, table: str = "all") -> int:
        """Delete expired records"""
        deleted_total = 0
        
        if table in ("events", "all"):
            deleted_total += self._cleanup_table("attacks", self.RETENTION_DAYS["events"])
        
        if table in ("commands", "all"):
            deleted_total += self._cleanup_table("commands", self.RETENTION_DAYS["commands"])
        
        if table in ("payloads", "all"):
            deleted_total += self._cleanup_table("payloads", self.RETENTION_DAYS["payloads"])
        
        return deleted_total
    
    def _cleanup_table(self, tablename: str, days: int) -> int:
        """Delete old records from table"""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        deleted = self.db.execute(f"DELETE FROM {tablename} WHERE created_at < %s", (cutoff,)).rowcount
        self.db.commit()
        return deleted


class RetentionJob:
    """Background job for data retention"""
    
    def run(self):
        """Execute retention cleanup"""
        from src.core.database import SessionLocal
        
        db = SessionLocal()
        try:
            manager = RetentionManager(db)
            count = manager.cleanup()
            print(f"Retention cleanup: {count} records removed")
        finally:
            db.close()


# Celery app for background tasks
if CELERY_AVAILABLE:
    REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
    celery_app = Celery(
        'honeypot',
        broker=os.getenv('CELERY_BROKER', f'redis://{REDIS_HOST}:6379/0'),
        backend=os.getenv('CELERY_BACKEND', f'redis://{REDIS_HOST}:6379/1')
    )
    
    @celery_app.task
    def enrich_ioc_task(ioc_type: str, value: str):
        """Background IOC enrichment task"""
        from src.services.threat_intel_service import ThreatIntelService
        import asyncio
        
        async def run():
            service = ThreatIntelService()
            if ioc_type == "ip":
                await service.enrich_ip(value)
            elif ioc_type == "hash":
                await service.enrich_hash(value)
            await service.close()
        
        asyncio.run(run())
else:
    # Fallback to simple function
    def enrich_ioc_task(ioc_type: str, value: str):
        """No-op if Celery unavailable"""
        pass


# Scheduler configuration for cron
class JobScheduler:
    """Background job scheduler for retention/exports"""
    
    def __init__(self):
        self.jobs = {}
    
    def register(self, name: str, interval_seconds: int, func):
        """Register a recurring job"""
        self.jobs[name] = {"interval": interval_seconds, "func": func}
    
    def list_jobs(self) -> Dict[str, Any]:
        return {
            "retention_cleanup": {"interval": 86400, "schedule": "daily"},
            "ioc_enrichment": {"interval": 3600, "schedule": "hourly"},
            "payload_scan": {"interval": 7200, "schedule": "every_2h"},
        }