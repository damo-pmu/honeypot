"""SQLAlchemy database configuration and models - PostgreSQL integration"""
import os
from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime, Text, ForeignKey, JSON, DECIMAL, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime
from typing import Generator

# Database URL from environment (set in docker-compose.yml)
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://honeypot:demo@postgres:5432/honeypot")

# Create engine with connection pooling
engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=10, max_overflow=20)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# SQLAlchemy Models
class AttackerDB(Base):
    __tablename__ = "attackers"
    
    ip = Column(String(45), primary_key=True)
    geoip = Column(JSON, nullable=True)
    asn = Column(String(50), nullable=True)
    first_seen = Column(DateTime(timezone=True), default=datetime.utcnow)
    last_seen = Column(DateTime(timezone=True), default=datetime.utcnow)
    threat_score = Column(Integer, default=0)
    classification = Column(String(30), default="UNKNOWN")
    reputation = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=True)


class SessionDB(Base):
    __tablename__ = "sessions"
    
    id = Column(String(100), primary_key=True)
    attacker_ip = Column(String(45), ForeignKey("attackers.ip", ondelete="CASCADE"), nullable=False)
    protocol = Column(String(20), nullable=True)
    start_time = Column(DateTime(timezone=True), default=datetime.utcnow)
    end_time = Column(DateTime(timezone=True), nullable=True)
    interaction_count = Column(Integer, default=0)
    duration_seconds = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=True)


class CommandDB(Base):
    __tablename__ = "commands"
    __table_args__ = (
        Index('idx_commands_session_ts', 'session_id', 'timestamp'),
        Index('idx_commands_flagged', 'flagged'),
    )
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(100), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False)
    command = Column(Text, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=datetime.utcnow)
    flagged = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)


class AttackDB(Base):
    __tablename__ = "attacks"
    __table_args__ = (
        Index('idx_attacks_ts', 'timestamp'),
        Index('idx_attacks_session', 'session_id'),
        Index('idx_attacks_severity', 'severity'),
    )
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(100), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False)
    attacker_ip = Column(String(45), nullable=False)  # Denormalized for fast queries
    timestamp = Column(DateTime(timezone=True), default=datetime.utcnow)
    attack_type = Column(String(50), nullable=True)  # SCAN, BRUTE_FORCE, MALWARE_DOWNLOAD, etc.
    payload = Column(Text, nullable=True)
    ioc_value = Column(Text, nullable=True)
    ioc_type = Column(String(20), nullable=True)
    severity = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)


class IOCDb(Base):
    __tablename__ = "ioc_indicators"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_type = Column(String(20), nullable=False)
    value = Column(Text, nullable=False)
    first_seen = Column(DateTime(timezone=True), default=datetime.utcnow)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    confidence = Column(DECIMAL(3, 2), default=1.0)
    source = Column(String(100), default="scan")
    hit_count = Column(Integer, default=1)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=True)


class IOCSessionLink(Base):
    __tablename__ = "ioc_session_link"
    
    ioc_id = Column(Integer, ForeignKey("ioc_indicators.id", ondelete="CASCADE"), primary_key=True)
    session_id = Column(String(100), ForeignKey("sessions.id", ondelete="CASCADE"), primary_key=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)


def get_db() -> Generator[Session, None, None]:
    """Dependency for FastAPI endpoints - provides database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database tables - called on app startup"""
    Base.metadata.create_all(bind=engine)