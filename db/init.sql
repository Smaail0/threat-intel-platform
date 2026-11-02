CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS attack_sessions (
    id UUID PRIMARY KEY,
    honeypot_node VARCHAR(50),
    service VARCHAR(20),
    attacker_ip INET,
    attacker_port INTEGER,
    timestamp TIMESTAMPTZ NOT NULL,
    ai_summary TEXT,
    threat_score INTEGER
);

CREATE TABLE IF NOT EXISTS session_events (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID REFERENCES attack_sessions(id) ON DELETE CASCADE,
    event_type VARCHAR(50),
    timestamp TIMESTAMPTZ NOT NULL,
    payload JSONB
);

CREATE INDEX IF NOT EXISTS idx_sessions_ip 
ON attack_sessions(attacker_ip);

CREATE INDEX IF NOT EXISTS idx_sessions_timestamp 
ON attack_sessions(timestamp);

CREATE INDEX IF NOT EXISTS idx_events_timestamp 
ON session_events(timestamp);

CREATE INDEX IF NOT EXISTS idx_events_payload 
ON session_events USING gin(payload);