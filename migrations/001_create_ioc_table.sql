-- IOC Indicators table migration
-- Stores detected IOCs with hit counts and relationships

CREATE TABLE IF NOT EXISTS ioc_indicators (
    id SERIAL PRIMARY KEY,
    ioc_type VARCHAR(20) NOT NULL CHECK (ioc_type IN ('hash', 'ip', 'domain', 'url')),
    value TEXT NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE,
    confidence DECIMAL(3, 2) DEFAULT 1.0 CHECK (confidence >= 0 AND confidence <= 1),
    source VARCHAR(100) DEFAULT 'scan',
    hit_count INTEGER DEFAULT 1,
    related_attacker_ip VARCHAR(45),
    related_session_id TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc_indicators(value);
CREATE INDEX IF NOT EXISTS idx_ioc_type ON ioc_indicators(ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_hit_count ON ioc_indicators(hit_count DESC);
CREATE INDEX IF NOT EXISTS idx_ioc_first_seen ON ioc_indicators(first_seen DESC);

-- Prevent duplicate IOCs (value should be unique per type)
CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_unique ON ioc_indicators(ioc_type, value);