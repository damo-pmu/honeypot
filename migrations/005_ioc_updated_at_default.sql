-- Add updated_at default to ioc_indicators (migration 005)
-- Applied post-cleanup to fix schema mismatch

ALTER TABLE ioc_indicators 
    ALTER COLUMN updated_at SET DEFAULT NOW();

-- Optional: auto-update trigger on row modification
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_ioc_indicators_updated_at ON ioc_indicators;
CREATE TRIGGER update_ioc_indicators_updated_at 
    BEFORE UPDATE ON ioc_indicators 
    FOR EACH ROW 
    EXECUTE PROCEDURE update_updated_at_column();