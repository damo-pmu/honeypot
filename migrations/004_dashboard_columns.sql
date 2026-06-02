-- Migration 004: Add missing columns for dashboard API
-- protocol on attacks table
-- country and threat_level on attackers table  
-- attacker_ip on commands table

ALTER TABLE attacks ADD COLUMN IF NOT EXISTS protocol VARCHAR(20);
ALTER TABLE attackers ADD COLUMN IF NOT EXISTS country VARCHAR(2);
ALTER TABLE attackers ADD COLUMN IF NOT EXISTS threat_level VARCHAR(20) DEFAULT 'unknown';
ALTER TABLE commands ADD COLUMN IF NOT EXISTS attacker_ip VARCHAR(45);