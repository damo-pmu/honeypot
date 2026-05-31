# MCD - Modèle Conceptuel de Données

```
┌─────────────────────────────────────────────────────────────────┐
│                        ATTACKER                                 │
├─────────────────────────────────────────────────────────────────┤
│ PK: ip (VARCHAR(45))           ┌─────────────────────────────┐   │
│    geoip (JSON)                │ INDEX: first_seen DESC      │   │
│    asn (VARCHAR)               │ INDEX: threat_score DESC    │   │
│    first_seen (TIMESTAMP)       │ INDEX: classification       │   │
│    last_seen (TIMESTAMP)       └─────────────────────────────┘   │
│    threat_score (INT)                                            │
│    classification (THREAT_CLASS)                                 │
│    reputation (VARCHAR)                                          │
│    created_at (TIMESTAMP)                                        │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    │ 1
                                    │
                                    │ N
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                         SESSION                                 │
├─────────────────────────────────────────────────────────────────┤
│ PK: id (UUID/TEXT)             ┌─────────────────────────────┐   │
│ FK: attacker_ip → attacker.ip  │ INDEX: attacker_ip          │   │
│    protocol (VARCHAR)          │ INDEX: start_time DESC      │   │
│    start_time (TIMESTAMP)       │ INDEX: interaction_count    │   │
│    end_time (TIMESTAMP)         └─────────────────────────────┘   │
│    interaction_count (INT)                                       │
│    duration_seconds (INT)                                        │
│    created_at (TIMESTAMP)                                        │
│    updated_at (TIMESTAMP)                                        │
└─────────────────────────────────────────────────────────────────┘
         │                       │                       │
         │ 1                     │ N                     │ N
         ▼                       ▼                       ▼
┌──────────────────────┐ ┌──────────────────────┐ ┌──────────────────────┐
│      COMMAND         │ │        ATTACK        │ │   IOC_SESSION        │
├──────────────────────┤ ├──────────────────────┤ ├──────────────────────┤
│ PK: id (SERIAL)     │ │ PK: id (SERIAL)    │ │ PK: (ioc_id, sess_id)│
│ FK: session_id       │ │ FK: session_id       │ │ FK: ioc_id → ioc    │
│    command (TEXT)    │ │ FK: attacker_ip     │ │ FK: session_id → sess│
│    timestamp         │ │    attack_type       │ └──────────────────────┘
│    flagged (BOOL)    │ │    payload (TEXT)    │
└──────────────────────┘ │    ioc_value (TEXT)  │
                         │    ioc_type (ENUM)   │
                         │    severity (INT)    │
                         │    created_at        │
                         └──────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      IOC_INDICATOR                              │
├─────────────────────────────────────────────────────────────────┤
│ PK: id (SERIAL)                 ┌─────────────────────────────┐  │
│    ioc_type (ENUM)              │ INDEX: value (UNIQUE)       │  │
│    value (TEXT)                 │ INDEX: ioc_type             │  │
│    first_seen (TIMESTAMP)        │ INDEX: hit_count DESC       │  │
│    last_seen (TIMESTAMP)                                          │
│    confidence (DECIMAL)                                        │
│    source (VARCHAR)                                              │
│    hit_count (INT)                                             │
└─────────────────────────────────────────────────────────────────┘
```

## Relations Principales

| Relation | Cardinalité | FK | Index |
|----------|-------------|-----|-------|
| Attacker → Session | 1 → N | ✅ `session.attacker_ip` | ✅ sur `attacker_ip` |
| Session → Command | 1 → N | ✅ `command.session_id` | ✅ sur `session_id` |
| Session → Attack | 1 → N | ✅ `attack.session_id` | ✅ sur `session_id` |
| IOC ↔ Session | N ↔ M | Via `ioc_session` | Via FK sur session_id |

## Queries Optimisées

```sql
-- Toutes les sessions d'un attaquant
SELECT s.* FROM sessions s WHERE s.attacker_ip = $ip;

-- Historique complet d'un attaquant (sessions + commands + attacks + iocs)
SELECT s.id, s.start_time, s.end_time, 
       c.command, c.flagged,
       a.attack_type, a.severity
FROM sessions s
LEFT JOIN commands c ON s.id = c.session_id
LEFT JOIN attacks a ON s.id = a.session_id
WHERE s.attacker_ip = $ip
ORDER BY s.start_time DESC;

-- Top IOCs avec sessions associées
SELECT i.value, i.hit_count, COUNT(is.session_id) as sessions_using
FROM ioc_indicators i
JOIN ioc_session is ON i.id = is.ioc_id
GROUP BY i.id
ORDER BY i.hit_count DESC;
```

## Bonnes Pratiques (Guideline Projet)

1. **Toutes les FK doivent être explicites** dans les modèles SQLAlchemy
2. **`created_at`/`updated_at`** sur chaque table pour l'audit
3. **Index sur colonnes de jointure fréquente**
4. **Timestamps en UTC systématiquement**
5. **Relations Pydantic avec `Optional[...]` et listes pour navigation inverse**