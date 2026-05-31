-- Response engine tables
-- Track all responses sent and decoy assets deployed

-- Responses sent to attackers
CREATE TABLE IF NOT EXISTS responses (
    id SERIAL PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    attacker_ip VARCHAR(45) NOT NULL,
    response_type VARCHAR(30),
    template_name TEXT,
    content TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_responses_session ON responses(session_id);
CREATE INDEX idx_responses_attacker ON responses(attacker_ip);
CREATE INDEX idx_responses_timestamp ON responses(timestamp DESC);

-- Decoy assets deployed
CREATE TABLE IF NOT EXISTS decoys (
    id SERIAL PRIMARY KEY,
    template_name TEXT,
    asset_type VARCHAR(30), -- file, config, credential
    fake_path TEXT,
    fake_content TEXT,
    session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_decoys_template ON decoys(template_name);
CREATE INDEX idx_decoys_session ON decoys(session_id);