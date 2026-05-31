# ADR-001: Honeypot Threat Intelligence Framework Architecture

## Status
Proposed

## Context
Construire une plateforme SOC-ready de collecte et analyse d'attaques, avec isolation stricte et extensibilité aux protocoles multiples.

## Decision

### 1. Architecture Logicielle
- **Clean Architecture + Hexagonal** pour isolation totale du noyau métier
- **DDD Light** : Attack, Session, Attacker comme entités principales
- **Modularité** : chaque protocole dans son package indépendant

### 2. Stack Technique (Conforme au cahier des charges)
```
API Layer:    FastAPI + Pydantic v2
Database:     PostgreSQL + SQLAlchemy 2.x + Alembic
Messaging:    Redis (cache) + RabbitMQ (events)
Observability: Prometheus + Grafana + OpenTelemetry
Logging:      structlog (JSON)
Security:     OAuth2/JWT (API) uniquement
```

## 3. Intégration Protocoles (Docker-Only)
Services Cowrie/Dionaea/Honeyd intégrés via docker-compose :

```yaml
services:
  api:          # FastAPI honeypot orchestrator
  cowrie:       # SSH/Telnet honeypot
  dionaea:      # FTP/SMB/HTTP malware honeypot  
  postgresql:   # DB stockage événements
  redis:        # Cache + queue
  rabbitmq:     # Event messaging
  prometheus:   # Metrics collection
  grafana:      # Dashboard SOC
```

Chaque honeypot expose un socket JSON pour ingérer les événements.

### 4. Classification Comportementale
Scores basés sur :
- Timing (latence, burst) → - comportement humain vs bot
- Diversité commandes → profondeur d'exploration
- Patterns → classification ML-ready

### 5. Scoring Engine (Règles configurables)
```yaml
brute_force: 20
sql_injection_attempt: 30
malware_upload: 50
credential_stuffing: 25
port_scan: 15
ai_agent_pattern: -10  # Bonus pour patterns IA
```

## Consequences

### Positive
- Extensibilité maximale (nouveaux protocoles via plugins)
- Isolation totale via Docker (aucune interaction hôte)
- Observabilité SOC-ready via Prometheus/Grafana
- Classification comportementale avancée
- **Portable : docker-compose up -d lance tout**

### Negative
- Images Docker lourdes (Cowrie/Dionaea ~500MB)
- Ressources consommées (8GB RAM recommandé)
- Complexité orchestration initiale

## Alternatives Evaluées
1. **Cowrie standalone** : Rejeté - pas assez d'extensibilité
2. **T-Pot** : Rejeté - trop lourd, pas modulaire
3. **Reinventer serveurs** : Rejeté - sécurité, maintenance

## Decision Outcome
On adopte l'approche modulaire avec intégration Cowrie/Dionaea/Honeyd via docker-compose.