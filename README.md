# 🍯 Honeypot Threat Intelligence Framework

[![CI](https://github.com/damo-pmu/honeypot/actions/workflows/ci.yml/badge.svg)](https://github.com/damo-pmu/honeypot/actions)

Framework SOC-ready pour capturer, analyser et classer les attaques.

## 🎯 Features

| Module | Status |
|--------|--------|
| Attackers CRUD API | ✅ |
| Sessions Tracking | ✅ |
| Commands Logging | ✅ |
| Scoring Engine | ✅ |
| Behavior Classification | ✅ |
| Database Queries | ✅ |
| GeoIP Enrichment | ✅ |
| Docker/Cowrie Integration | ✅ |
| **Dashboard temps réel** | ✅ |

## 🚀 Démarrage rapide

```bash
docker-compose up -d
curl http://localhost:8000/health
```

## 📡 Endpoints disponibles

| Endpoint | Description |
|----------|-------------|
| `/attackers` | Gestion des attaquant·e·s |
| `/sessions` | Sessions d'attaque |
| `/commands` | Commandes suspectes |
| `/behavior/classify` | Classification timing |
| `/analytics/*` | Queries SQL |
| `/enrichment/ip` | GeoIP lookup |
| `/dashboard/` | Monitoring temps réel |
| `/dashboard/login` | Authentification |
| `/dashboard/stream` | SSE endpoint (auth requise) |
| `/dashboard/stats` | Statistiques JSON |

## 📊 Dashboard

URL : `http://honeypot.hiddenlabs.cc`

### Auth minimale
- Cookie-based session (HttpOnly, SameSite=Strict)
- Password configuré via `DASHBOARD_PASSWORD` dans `.env`

### Fonctionnalités
- ✅ Monitoring temps réel (SSE)
- ✅ Statistiques dynamiques
- ✅ Carte interactive (Leaflet.js + ipapi.co)
- ✅ Filtres par type d'attaque
- ✅ Reconnection automatique

### Configuration Apache
Fichier : `~/.hermes/honeypot-config/honeypot.hiddenlabs.cc.conf`

```apache
ProxyPass /dashboard/stream http://localhost:8000/dashboard/stream connectiontimeout=5
ProxyPass /dashboard/ http://localhost:8000/dashboard/
```

## 🛡️ Architecture

```
src/
├── api/          # FastAPI routers
├── core/         # Entités/domain
├── detection/    # Classification ML-ready
├── honeypots/    # SSH/Telnet/FTP (Docker)
├── infrastructure/ # DB/Logging/GeoIP
└── workers/      # Event ingestion
```

## 📜 Licence

MIT - Usage defensif uniquement