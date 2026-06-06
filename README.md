# 🍯 Honeypot Threat Intelligence Framework

[![CI](https://github.com/damo-pmu/honeypot/actions/workflows/ci.yml/badge.svg)](https://github.com/damo-pmu/honeypot/actions)

Framework SOC-ready pour capturer, analyser et classer les attaques.

## 🎯 Features

| Module | Status | Docs |
|--------|--------|------|
| Attackers CRUD API | ✅ | [docs/APIS.md](docs/APIS.md) |
| Sessions Tracking | ✅ | [docs/APIS.md](docs/APIS.md) |
| Commands Logging | ✅ | [docs/APIS.md](docs/APIS.md) |
| Scoring Engine | ✅ | [docs/SCORING.md](docs/SCORING.md) |
| Behavior Classification | ✅ | [docs/SERVICES.md](docs/SERVICES.md) |
| Database Queries | ✅ | [docs/QUERIES.md](docs/QUERIES.md) |
| GeoIP Enrichment | ✅ | [docs/APIS.md](docs/APIS.md) |
| Docker/Cowrie Integration | ✅ | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| **Dashboard temps réel** | ✅ | [docs/APIS.md](docs/APIS.md) |

## 🚀 Démarrage rapide

```bash
docker-compose up -d
curl http://localhost:8000/health
```

## 📡 Endpoints disponibles

| Endpoint | Description | Docs |
|----------|-------------|------|
| `/attackers` | Gestion des attaquant·e·s | [APIS.md](docs/APIS.md#attackers-api) |
| `/sessions` | Sessions d'attaque | [APIS.md](docs/APIS.md#sessions-api) |
| `/commands` | Commandes suspectes | [APIS.md](docs/APIS.md#commands-api) |
| `/behavior/classify` | Classification timing | [APIS.md](docs/APIS.md#behavior-api) |
| `/analytics/*` | Queries SQL | [APIS.md](docs/APIS.md#analytics-api) |
| `/enrichment/ip` | GeoIP lookup | [APIS.md](docs/APIS.md#enrichment-api) |
| `/dashboard/` | Monitoring temps réel | [APIS.md](docs/APIS.md#dashboard-api) |

## 🛠️ Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Architecture Docker + workers |
| [APIS.md](docs/APIS.md) | Endpoints API complets |
| [DATA_MODEL.md](docs/DATA_MODEL.md) | Schéma DB + relations |
| [DATABASE.md](docs/DATABASE.md) | Config + maintenance |
| [QUERIES.md](docs/QUERIES.md) | Queries SQL + IOC search |
| [SCORING.md](docs/SCORING.md) | Scoring + classification |
| [SERVICES.md](docs/SERVICES.md) | Services métiers |
| [WORKERS.md](docs/WORKERS.md) | Workers + response engine |
| [HANDOVER.md](docs/HANDOVER.md) | Guide de reprise exact |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Guidelines contributeurs |

## 📊 Dashboard

URL : `http://honeypot.hiddenlabs.cc`

### Features
- Monitoring temps réel (WebSocket + fallback HTTP)
- Statistiques dynamiques
- Carte interactive
- Filtres par type d'attaque
- Reconnection automatique

## 🛡️ Architecture

```
src/
├── api/endpoints/   # FastAPI routers
├── core/           # Entités/domain
├── services/       # Business logic
├── workers/        # Event ingestion
└── response/       # Decoy templates
```

## 📜 Licence

MIT - Usage défensif uniquement