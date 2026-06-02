-- Full schema with proper FKs and indexes
-- Run after 001_create_ioc_table.sql

-- Drop old table if needed and recreate with proper structure
DROP TABLE IF EXISTS attacks CASCADE;
DROP TABLE IF EXISTS commands CASCADE;
DROP TABLE IF EXISTS ioc_session_link CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS attackers CASCADE;

-- Attacker table
CREATE TABLE attackers (
    ip VARCHAR(45) PRIMARY KEY,
    geoip JSONB,
    asn VARCHAR(50),
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    threat_score INTEGER DEFAULT 0,
    classification VARCHAR(30) DEFAULT 'UNKNOWN',
    reputation VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_attackers_first_seen ON attackers(first_seen DESC);
CREATE INDEX idx_attackers_threat_score ON attackers(threat_score DESC);
CREATE INDEX idx_attackers_classification ON attackers(classification);

-- Session table with FK to attacker
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    attacker_ip VARCHAR(45) NOT NULL REFERENCES attackers(ip) ON DELETE CASCADE,
    protocol VARCHAR(20),
    start_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    end_time TIMESTAMP WITH TIME ZONE,
    interaction_count INTEGER DEFAULT 0,
    duration_seconds INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_sessions_attacker_ip ON sessions(attacker_ip);
CREATE INDEX idx_sessions_start_time ON sessions(start_time DESC);
CREATE INDEX idx_sessions_interaction_count ON sessions(interaction_count);

-- Command table with FK to session
CREATE TABLE commands (
    id SERIAL PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    command TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    flagged BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_commands_session_id ON commands(session_id);
CREATE INDEX idx_commands_flagged ON commands(flagged) WHERE flagged = TRUE;
CREATE INDEX idx_commands_timestamp ON commands(timestamp DESC);

-- Attack table with FK to session (denormalized attacker_ip for fast queries)
CREATE TABLE attacks (
    id SERIAL PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    attacker_ip VARCHAR(45) NOT NULL, -- Denormalized for performance
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    attack_type VARCHAR(50),
    payload TEXT,
    ioc_value TEXT,
    ioc_type VARCHAR(20),
    severity INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_attacks_session_id ON attacks(session_id);
CREATE INDEX idx_attacks_attacker_ip ON attacks(attacker_ip);
CREATE INDEX idx_attacks_timestamp ON attacks(timestamp DESC);
CREATE INDEX idx_attacks_severity ON attacks(severity DESC);

-- IOC Indicator table (updated)
CREATE TABLE ioc_indicators (
    id SERIAL PRIMARY KEY,
    ioc_type VARCHAR(20) NOT NULL CHECK (ioc_type IN ('hash', 'ip', 'domain', 'url')),
    value TEXT NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE,
    confidence DECIMAL(3, 2) DEFAULT 1.0 CHECK (confidence >= 0 AND confidence <= 1),
    source VARCHAR(100) DEFAULT 'scan',
    hit_count INTEGER DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);

CREATE UNIQUE INDEX idx_ioc_unique ON ioc_indicators(ioc_type, value);
CREATE INDEX idx_ioc_value ON ioc_indicators(value);
CREATE INDEX idx_ioc_type ON ioc_indicators(ioc_type);
CREATE INDEX idx_ioc_hit_count ON ioc_indicators(hit_count DESC);
CREATE INDEX idx_ioc_first_seen ON ioc_indicators(first_seen DESC);

-- Many-to-Many link between IOC and Session
CREATE TABLE ioc_session_link (
    ioc_id INTEGER NOT NULL REFERENCES ioc_indicators(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (ioc_id, session_id)
);

CREATE INDEX idx_ioc_session_session ON ioc_session_link(session_id);
CREATE INDEX idx_ioc_session_ioc ON ioc_session_link(ioc_id);