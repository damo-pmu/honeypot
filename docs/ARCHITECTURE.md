# Architecture Technique - Honeypot SOC

> Code-first documentation - alignée avec docker-compose.yml implémenté

## Infrastructure Docker

### Services déployés (docker-compose.yml)

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| api | Custom (python:3.11) | 8000 | FastAPI honeypot framework |
| postgres | postgres:15-alpine | 5432 | Persisté PostgreSQL |
| redis | redis:7-alpine | 6379 | Cache + threat intel queue |
| rabbitmq | rabbitmq:3-management-alpine | 5672 | Messaging inter-services |
| cowrie | Custom build | 22/23 | SSH/Telnet honeypot |
| worker | Custom | - | Cowrie log ingestion |
| prometheus | prom/prometheus | 9090 | Métriques temps réel |
| grafana | grafana/grafana:11.0.0 | 3000 | Dashboard monitoring |

### Volumes persistés
- `postgres_data` : Base de données
- `cowrie_logs` : Logs JSON Cowrie
- `cowrie_data` : SSH keys
- `grafana_data` : Dashboard persisté

### Réseaux
- Tous services sur réseau Docker par défaut
- Ports exposés uniquement localhost (reverse proxy Apache)

## Architecture applicative

```
┌─────────────────────────────────────────────────────────────┐
│                        Dashboard                          │
│              (HTML + SSE) http://localhost:8000           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      FastAPI App                          │
│                   (app.py + routers)                     │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐ │
│  │attackers │ sessions │ commands │ behavior │ ioc      │ │
│  └──────────┴──────────┴──────────┴──────────┴──────────┘ │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐ │
│  │response  │ analytics│enrichment│ dashboard │ attacks  │ │
│  └──────────┴──────────┴──────────┴──────────┴──────────┘ │
└─────────────────────────────────────────────────────────────┘
       │               │               │              │
       ▼               ▼               ▼              ▼
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│PostgreSQL│    │   Redis  │    │Prometheus│    │ Threat   │
│(écriture)│    │(cache)   │    │(metrics) │    │ Intel    │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
       ▲
       │
┌─────────────────────────────────────────────────────────────┐
│                     Cowrie Worker                         │
│              (src/workers/cowrie_ingest.py)               │
│   - Ingest logs JSON                                       │
│   - Extract IOCs                                         │
│   - Send events to API                                    │
└─────────────────────────────────────────────────────────────┘
       ▲
       │
┌─────────────────────────────────────────────────────────────┐
│                       Cowrie Honeypot                     │
│              (SSH/Telnet sur ports 22/23)                  │
└─────────────────────────────────────────────────────────────┘
```

## Endpoints d'entrée/sortie

### Ingress (écriture)
- `POST /attackers` - Création attaquant
- `POST /sessions` - Création session
- `POST /commands` - Logging command
- `POST /attacks/log` - Logging attaque
- `POST /dashboard/internal/events` - Events (worker)
- `POST /dashboard/internal/sessions` - Sessions (worker)

### Egress (lecture)
- `GET /sessions` - List sessions
- `GET /attackers` - List attackers
- `GET /commands` - List commands
- `GET /dashboard/*` - Dashboard UI/API
- `GET /analytics/*` - Analytics queries
- `GET /metrics` - Prometheus

## Sécurité

### Configuration
- Ports localhost uniquement (reverse proxy Apache)
- `DASHBOARD_PASSWORD` pour auth dashboard
- LLM local uniquement (pas d'API externe)
- Variables d'environnement depuis `.env`

### Fail2ban integration
```bash
# /etc/fail2ban/filter.d/cowrie.conf
# JSON log parsing + banning attacker IPs
```

## Démarrage

```bash
# Démarrage complet
docker-compose up -d

# Vérification santé
curl http://localhost:8000/health

# Logs worker
docker logs honeypot_worker
```

### Flow d'ingestion événements

```mermaid
flowchart LR
    A[Cowrie SSH/Telnet] --> B[cowrie.json]
    B --> C[Worker cowrie_ingest.py]
    C --> D{Event Type}
    D -->|login| E[/attackers]
    D -->|login| F[/sessions]
    D -->|login| G[/attacks/log BRUTE_FORCE]
    D -->|command| H[/commands]
    D -->|command| I[/ioc/scan inline]
    D -->|download| J[/ioc/store url]
    D -->|download| K[/attacks/log MALWARE_DOWNLOAD]
```