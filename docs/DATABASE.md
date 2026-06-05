# Base de Données - Configuration & Maintenance

> Code-first documentation - alignée avec src/core/database.py

## Configuration SQLAlchemy

### Connexion
```python
# src/core/database.py:10-13
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://honeypot:demo@postgres:5432/honeypot")

engine = create_engine(
    DATABASE_URL, 
    pool_pre_ping=True,   # Vérifie connexion avant requête
    pool_size=10,         # Connexions persistantes
    max_overflow=20       # Au-delà du pool
)
```

### Session pattern
```python
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

Usage FastAPI : `db: Session = Depends(get_db)`

## Indexations

### Tables avec index
| Table | Index | Colonnes |
|-------|-------|----------|
| commands | `idx_commands_session_ts` | session_id, timestamp |
| commands | `idx_commands_flagged` | flagged |
| attacks | `idx_attacks_ts` | timestamp |
| attacks | `idx_attacks_session` | session_id |
| attacks | `idx_attacks_severity` | severity |
| payloads | `idx_payloads_sha256` | sha256 |
| payloads | `idx_payloads_first_seen` | first_seen |

## Scripts maintenance

### db_maintenance.py

| Command | Fonction | Tables concernées |
|---------|----------|-------------------|
| `timestamps` | Normalise timestamps manquants | attacks, commands |
| `retention` | Policy rétention (72h) | attacks (severity<50), commands, sessions |
| `vacuum` | Analyse + vacuum PostgreSQL | Toutes |
| `indexes` | Crée index manquants | Toutes |
| `cleanup-healthcheck` | Supprime sessions healthcheck (127.0.0.1) | sessions, attacks |

### Utilisation
```bash
# À lancer depuis le container API
python scripts/db_maintenance.py timestamps
python scripts/db_maintenance.py retention
python scripts/db_maintenance.py cleanup-healthcheck
```

## Requêtes analytiques

### Statistiques sessions
```sql
-- Sessions actives
SELECT COUNT(*) FROM sessions WHERE end_time IS NULL;

-- Top attackers
SELECT attacker_ip, COUNT(*) as attacks 
FROM attacks 
GROUP BY attacker_ip 
ORDER BY attacks DESC 
LIMIT 10;
```

### IOC hotspots
```sql
SELECT i.value, COUNT(l.session_id) as session_count
FROM ioc_indicators i
JOIN ioc_session_link l ON i.id = l.ioc_id
WHERE i.ioc_type = 'ip'
GROUP BY i.value
ORDER BY session_count DESC;
```

## Backup/Restore

### Volumes Docker
- `postgres_data` : Volume nommé pour persistence
- Sauvegarde : `docker exec postgres pg_dump -U honeypot honeypot > backup.sql`

### Restore
```bash
docker cp backup.sql honeypot_postgres_1:/tmp/
docker exec -it honeypot_postgres_1 psql -U honeypot -f /tmp/backup.sql honeypot
```

## Monitoring DB

### Métriques exportées
| Métrique | Purpose |
|----------|---------|
| `honeypot_db_queries_total` | Nb requêtes par table/operation |
| `honeypot_db_query_duration_seconds` | Latence requêtes |

### Queries lentes
Surveiller via Prometheus + Grafana dashboard `PostgreSQL`