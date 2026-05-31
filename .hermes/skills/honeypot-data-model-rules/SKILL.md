---
name: honeypot-data-model-rules
category: honeypot-development-framework
description: Data modeling guidelines for honeypot framework - FK, indexes, timestamps, relations
version: 1.0.0
---

# Skill: Honeypot Data Modeling Guidelines

## Trigger
When designing or modifying database entities in honeypot projects.

## Rules (MUST FOLLOW)

### 1. Primary Keys
- Always explicit: `id SERIAL` for auto-increment or natural key (`ip VARCHAR(45)`)
- Never implicit or missing

### 2. Foreign Keys
```python
# ALWAYS include FK in Pydantic model
class Session(BaseModel):
    attacker_ip: str  # FK to attackers.ip - DOCUMENT THIS
    session_id: str   # FK to sessions.id - DOCUMENT THIS
```

### 3. Timestamps
- EVERY table gets `created_at TIMESTAMP DEFAULT NOW()`
- EVERY table gets `updated_at TIMESTAMP NULL`
- On updates: `updated_at = NOW()`

### 4. Indexes Required
| Column | When to Index |
|--------|---------------|
| FK columns (attacker_ip, session_id) | ALWAYS |
| timestamp columns | ALWAYS |
| hit_count, threat_score | If used in ORDER BY DESC |
| flagged | If filtered (partial index) |
| value (for IOCs) | UNIQUE constraint implied |

### 5. Inverse Relations (Pydantic)
Every entity must include Optional reverse relations for navigation:
```python
class Attacker(BaseModel):
    sessions: Optional[List[str]] = None  # Populated by query

class Session(BaseModel):
    commands: Optional[List[dict]] = None
    attacks: Optional[List[dict]] = None
    iocs: Optional[List[str]] = None
```

### 6. Many-to-Many Pattern
Use junction table with composite PK:
```sql
CREATE TABLE ioc_session_link (
    ioc_id INTEGER REFERENCES ioc_indicators(id) ON DELETE CASCADE,
    session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE,
    PRIMARY KEY (ioc_id, session_id)
);
-- Create index on each FK column
```

### 7. SQL Migration Template
```sql
-- Entity table
CREATE TABLE table_name (
    id SERIAL PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);

-- Indexes
CREATE INDEX idx_table_session_id ON table_name(session_id);
CREATE INDEX idx_table_created_at ON table_name(created_at DESC);
```

## Pitfalls
- ❌ Forgetting FK constraints leads to orphaned data
- ❌ Missing created_at breaks audit trails
- ❌ No indexes on queried columns = slow forensics queries
- ❌ Storing IOC_session_id as loose field instead of M2M link

## Verification
Run after schema changes:
```sql
-- Check FKs exist
SELECT conname FROM pg_constraint WHERE contype = 'f';

-- Check indexes
SELECT indexname FROM pg_indexes WHERE tablename = 'your_table';
```