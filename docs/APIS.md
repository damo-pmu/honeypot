# API Endpoints Reference - Honeypot SOC

> Code-first documentation - alignée avec src/api/endpoints/*.py

## Convention

Tous endpoints utilisent :
- FastAPI avec SQLAlchemy Session (`Depends(get_db)`)
- Responses : Pydantic models
- Security middleware : `AuditMiddleware` sur toutes les routes

> Note : cette documentation est alignée avec le code actuel. La branche `master` contient la version stable et fonctionnelle.

---

## Attackers API (`/attackers`)

### Endpoints
| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/attackers/` | Liste attaquant·e·s (max 100) | Non |
| POST | `/attackers/` | Créer/maj attaquant | Non |
| GET | `/attackers/{attacker_id}` | Détail attaquant | Non |

### Modèle
```python
# src/api/endpoints/attackers.py
class ThreatClass(str, Enum):
    BOT = "BOT"
    AUTOMATED_SCANNER = "AUTOMATED_SCANNER"  
    HUMAN_OPERATOR = "HUMAN_OPERATOR"
    SCRIPT_KIDDIE = "SCRIPT_KIDDIE"
    BOTNET_NODE = "BOTNET_NODE"
    POSSIBLE_AI_AGENT = "POSSIBLE_AI_AGENT"
    UNKNOWN = "UNKNOWN"
```

### Usage
```bash
# List
curl http://localhost:8000/attackers/

# Create
curl -X POST http://localhost:8000/attackers/ \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.1", "threat_score": 80}'
```

---

## Sessions API (`/sessions`)

### Endpoints
| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/sessions/` | Liste sessions | Non |
| POST | `/sessions/` | Créer session | Non |
| GET | `/sessions/{session_id}` | Détail session | Non |
| PUT | `/sessions/{session_id}/end` | Terminer session + durée | Non |

### Tables concernées
- `sessions` (création/lecture)
- `attackers` (auto-création si IP inconnue)
- Métriques Prometheus : `sessions_total`, `session_duration`, `sessions_active`

### Usage
```bash
# Create session
curl -X POST http://localhost:8000/sessions/ \
  -d '{"id": "uuid-cowrie", "attacker_ip": "10.0.0.1", "protocol": "SSH"}'

# End session
curl -X PUT http://localhost:8000/sessions/{id}/end
```

---

## Commands API (`/commands`)

### Endpoints
| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/commands/` | Liste commands (max 100) | Non |
| POST | `/commands/` | Logger command | Non |
| GET | `/commands/session/{session_id}` | Commands session | Non |

### Champs importants
- `flagged` : booléen pour comportement suspect
- `attacker_ip` : denormalisé pour queries rapides
- Index `idx_commands_session_ts` sur (session_id, timestamp)

---

## Behavior API (`/behavior`)

### Endpoints
| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/behavior/classify` | Classification menace | Non |

### Classification
```python
# src/response/llm_classifier.py
ThreatClass:
- AUTOMATED_SCANNER : nmap, masscan, nikto, sqlmap
- SCRIPT_KIDDIE : whoami, id, cat /etc/passwd
- POSSIBLE_AI_AGENT : commands systématiques < 20 chars
- UNKNOWN : données insuffisantes
```

### LLM Safety
- **LOCAL ONLY** : `LOCAL_LLM_MODEL` path
- **Fallback** : rule-based si LLM indisponible
- Sanitisation `{}` suppression dans prompt

---

## Analytics API (`/analytics`)

### Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/analytics/session-timeline/{session_id}` | Timeline formatée |
| GET | `/analytics/attack-feed` | Flux attaques formaté |

### Format response
```json
{
  "session_id": "uuid",
  "events": [{"timestamp", "action", "payload"}]
}
```

---

## Enrichment API (`/enrichment`)

### Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/enrichment/ip` | GeoIP lookup |
| GET | `/enrichment/ip/reputation/{ip}` | Réputation IP |
| GET | `/enrichment/url/check` | Vérif URL |
| GET | `/enrichment/hash/{hash_value}` | Vérif hash |
| GET | `/enrichment/ioc/{ioc_value}` | Enrichissement IOC |

### Sources
- `ipapi.co` : GeoIP (country, ASN)
- AbusesIPDB API : réputation (optionnel)
- VirusTotal : hash verification (optionnel)

---

## IOC API (`/ioc`)

### Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/ioc/scan` | Scan texte pour IOCs |
| POST | `/ioc/store` | Persister IOC |
| GET | `/ioc/top` | Top IOCs par hits |
| GET | `/ioc/type/{ioc_type}` | Filtre par type |
| GET | `/ioc/search/{ioc_value}` | Recherche IOC |
| POST | `/ioc/bulk-scan` | Scan multiple |

### Types IOC
- `hash` : MD5/SHA1/SHA256
- `ip` : IPv4 addresses
- `url` : URLs HTTP/HTTPS
- `domain` : Domain names

---

## Response API (`/response`)

### Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/response/analyze` | Analyse menace |
| POST | `/response/generate` | Génération réponse decoy |
| GET | `/response/templates` | Templates disponibles |
| GET | `/response/adversarial/{trap_type}` | Piège advers |
| GET | `/response/decoy/{template}` | Template spécifique |

### Templates
```python
# src/response/router.py
RESPONSE_TEMPLATES = {
    "cisco_router/show_version": "Cisco IOS config...",
    "cisco_router/running_config": "Router config...",
    "jenkins_instance/config": "Jenkins XML...",
    "windows_server/credentials": "NTLM hash...",
    "ai_challenge/cognitive_trap": "ERROR: Cognitive anomaly..."
}
```

### Decision Logic
```
interactions > 20 → TERMINATE (sécurité)
BOT/SCANNER → cisco_router decoy
AI_AGENT → cognitive challenge
SCRIPT_KIDDIE → windows credentials
HUMAN → jenkins config
UNKNOWN → cisco running_config
```

---

## Dashboard API (`/dashboard`)

### User-facing routes
| Method | Path | Description |
|--------|------|-------------|
| GET | `/dashboard/` | Dashboard UI home |
| GET | `/dashboard/analytics` | Analytics UI page |
| GET | `/dashboard/settings` | Settings UI page |
| GET | `/dashboard/login` | Dashboard login page |
| POST | `/dashboard/login` | Submit dashboard password |
| GET | `/dashboard/logout` | Logout from dashboard |

### API Endpoints
| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/dashboard/api/stats` | Stats JSON agrégées | Oui |
| GET | `/dashboard/api/live-feed` | Flux d’événements récents | Oui |
| GET | `/dashboard/api/analytics/threat-heatmap` | Heatmap des menaces | Oui |
| GET | `/dashboard/api/analytics/attacker-profiles` | Profils attaquants | Oui |
| GET | `/dashboard/api/analytics/command-patterns` | Patterns de commandes | Oui |
| GET | `/dashboard/api/analytics/ioc-summary` | Résumé IOC | Oui |
| GET | `/dashboard/api/analytics/payload-analysis` | Analyse payload | Oui |
| GET | `/dashboard/api/analytics/attack-taxonomy` | Taxonomie des attaques | Oui |
| GET | `/dashboard/api/analytics/correlations` | Corrélations d’attaques | Oui |
| GET | `/dashboard/api/export/threat-report` | Export JSON de report | Oui |
| GET | `/dashboard/api/export/attackers` | Export CSV des attaquants | Oui |
| GET | `/dashboard/api/search/sessions` | Recherche sessions | Oui |
| GET | `/dashboard/api/search/commands` | Recherche commands | Oui |
| GET | `/dashboard/ws/live` | WebSocket live feed | Oui |
| GET | `/dashboard/api/health` | Health check | Non |
| GET | `/dashboard/api/meta/endpoints` | Endpoints discovery | Non |

### Notes
- L’UI du dashboard est servie par FastAPI et protégée par cookie de session.
- Tous les endpoints `analytics`, `export`, `search`, `stats`, `live-feed` et WebSocket sont protégés par authentification.
- Le dashboard utilise un cookie de session `dash_session` (HttpOnly, SameSite=Strict).
- Password via `DASHBOARD_PASSWORD`.

### Templates Architecture
L'UI utilise une architecture Jinja2 modulaire avec `base.html` et blocks :
- **base.html** : Structure commune, blocks `title`, `content`, `page_styles`, `extra_js`
- **login.html**, **dashboard.html**, **dashboard_analytics.html**, **dashboard_settings.html** : étendent `base.html`
- **Assets** : `/static/css/dashboard.css` (dark theme, responsive), `/static/js/dashboard.js` (live feed)

```mermaid
flowchart LR
    A[Browser] --> B[WebSocket /dashboard/ws/live]
    B --> C[Server]
    C --> D{Ping ?}
    D -->|yes| E[Repondre pong]
    D -->|no| F[Maintenir la connexion]
    E --> A
    F --> A
```

---

## Attacks API (`/attacks`)

### Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/attacks/log` | Logger attaque |
| GET | `/attacks/session/{session_id}` | Attaques session |
| GET | `/attacks/feed` | Flux attaques |
| GET | `/attacks/metrics/summary` | Métriques résumées |

### Attack types
- `SCAN` : Reconnaissance
- `BRUTE_FORCE` : Auth attempts
- `COMMAND_EXECUTION` : Commands
- `MALWARE_DOWNLOAD` : Download

---

## Internal Endpoints

### Purpose
Routes utilisées par le worker Cowrie, pas exposées publiquement.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/internal/sessions` | Worker → création session |
| POST | `/internal/events` | Worker → logging événement |
| POST | `/internal/sessions/{id}/end` | Worker → fin session |
| GET | `/stream` | Legacy SSE endpoint (deprecated). Use WebSocket `/dashboard/ws/live` or internal POST events `/dashboard/internal/events` |
| POST | `/dashboard/internal/events` | Events (nouveau) |
| POST | `/dashboard/internal/sessions` | Sessions (nouveau) |

### CORS
Configuration restrictive via environnement :

| Variable | Purpose |
|----------|---------|
| `HONEYPOT_HOSTNAME` | Hostname pour origines génériques |
| `CORS_ALLOWED_ORIGINS` | Liste comma-separated d'origines autorisées |

Default: ports 3000, 5000, 9090 sur hostname configuré.
```python
# app.py
allow_methods = ["GET", "POST", "PUT", "DELETE"]
allow_headers = ["Content-Type", "Authorization"]
allow_credentials = True
```