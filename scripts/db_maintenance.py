#!/usr/bin/env python3
"""Database maintenance: indexes optimization and retention policy"""
import os
from datetime import datetime, timezone, timedelta, timezone
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

DB_USER = os.getenv("DB_USER", "honeypot")
DB_PASSWORD = os.getenv("PG_PASS", "demo")
DB_HOST = os.getenv("DB_HOST", "postgres")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "honeypot")

DATABASE_URL = os.getenv("DATABASE_URL", f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)

RETENTION_ATTACKS = 90
RETENTION_SESSIONS = 30


def create_indexes():
    """Create indexes if they don't exist (idempotent)"""
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_commands_session_ts 
            ON commands(session_id, timestamp);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_commands_flagged 
            ON commands(flagged);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_attacks_ts 
            ON attacks(timestamp);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_attacks_session 
            ON attacks(session_id);
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_attacks_severity 
            ON attacks(severity);
        """))
        conn.commit()
        print("Indexes created/verified")


def update_timestamps():
    """Batch update updated_at columns"""
    with engine.connect() as conn:
        now = datetime.now(timezone.utc)
        
        conn.execute(text("""
            UPDATE attackers SET updated_at = :now 
            WHERE updated_at IS NULL OR updated_at < :now
        """), {"now": now})
        
        conn.execute(text("""
            UPDATE sessions SET updated_at = :now 
            WHERE updated_at IS NULL OR updated_at < :now
        """), {"now": now})
        
        conn.commit()
        print(f"Timestamps updated: {now.isoformat()}")


def apply_retention():
    """Apply data retention policy - delete old records"""
    with engine.connect() as conn:
        cutoff_attacks = datetime.now(timezone.utc) - timedelta(days=RETENTION_ATTACKS)
        cutoff_sessions = datetime.now(timezone.utc) - timedelta(days=RETENTION_SESSIONS)
        
        # Purge old attacks
        result = conn.execute(text("""
            DELETE FROM attacks WHERE created_at < :cutoff
        """), {"cutoff": cutoff_attacks})
        attacks_deleted = result.rowcount
        
        # Purge old commands
        result = conn.execute(text("""
            DELETE FROM commands WHERE created_at < :cutoff
        """), {"cutoff": cutoff_attacks})
        commands_deleted = result.rowcount
        
        # Close stale sessions
        result = conn.execute(text("""
            UPDATE sessions SET end_time = NOW() 
            WHERE end_time IS NULL AND start_time < :cutoff
        """), {"cutoff": cutoff_sessions})
        sessions_closed = result.rowcount
        
        conn.commit()
        print(f"Retention: {attacks_deleted} attacks, {commands_deleted} commands, {sessions_closed} sessions closed")


def cleanup_healthcheck_sessions():
    """Delete sessions identified as healthchecks: localhost IP with zero interactions"""
    with engine.connect() as conn:
        # Delete attacks linked to healthcheck sessions first (FK cascade)
        result = conn.execute(text("""
            DELETE FROM attacks 
            WHERE session_id IN (
                SELECT id FROM sessions 
                WHERE attacker_ip = '127.0.0.1' AND interaction_count = 0
            )
        """))
        attacks_deleted = result.rowcount
        
        # Delete the healthcheck sessions
        result = conn.execute(text("""
            DELETE FROM sessions 
            WHERE attacker_ip = '127.0.0.1' AND interaction_count = 0
        """))
        sessions_deleted = result.rowcount
        
        conn.commit()
        print(f"Healthcheck cleanup: {sessions_deleted} sessions, {attacks_deleted} attacks removed")


def vacuum_tables():
    """Vacuum tables for performance (manual run)"""
    with engine.connect() as conn:
        conn.execute(text("VACUUM ANALYZE attacks, commands, sessions, attackers"))
        conn.commit()
        print("Vacuum complete")


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    
    if cmd == "timestamps":
        update_timestamps()
    elif cmd == "retention":
        apply_retention()
    elif cmd == "vacuum":
        vacuum_tables()
    elif cmd == "indexes":
        create_indexes()
    elif cmd == "cleanup-healthcheck":
        cleanup_healthcheck_sessions()
    else:
        print("Usage: db_maintenance.py [timestamps|retention|vacuum|indexes|cleanup-healthcheck]")