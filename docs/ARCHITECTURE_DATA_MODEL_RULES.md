# Skill: Honeypot Data Modeling Guidelines

## Trigger
When designing or modifying database entities in the honeypot project.

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
| hit_count, threat_score | If used in ORDER BY |
| flagged | If filtered (partial index) |

### 5. Inverse Relations
Pydantic models must include Optional reverse relations for queries:
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
    ioc_id INTEGER REFERENCES ioc_indicators(id),
    session_id TEXT REFERENCES sessions(id),
    PRIMARY KEY (ioc_id, session_id)
);
```

### 7. Query Optimization Examples
```sql
-- Attacker history (optimized)
SELECT s.id, s.start_time, c.command, a.attack_type, a.severity
FROM sessions s
LEFT JOIN commands c ON s.id = c.session_id
LEFT JOIN attacks a ON s.id = a.session_id
WHERE s.attacker_ip = $1  -- Uses idx_sessions_attacker_ip
ORDER BY s.start_time DESC; -- Uses idx_sessions_start_time
```

## Verification Checklist
- [ ] All FKs documented in model
- [ ] created_at/updated_at on all tables
- [ ] Index on FK columns
- [ ] Index on timestamp columns used in queries
- [ ] Inverse relations in Pydantic models
- [ ] Migration SQL reviewed