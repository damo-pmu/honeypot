# ROADMAP - Honeypot Threat Intelligence Framework

> **Méthode : Code → Test → Commit (30min cadences)**

---

## 🎯 Phase 1 : Core API Endpoints (J+1)

### Feature 1.1 - Attackers CRUD
- [ ] `GET /attackers` - List avec filtres (IP, classification, score)
- [ ] `POST /attackers` - Création via webhook Cowrie
- [ ] `GET /attackers/{id}` - Détail + sessions liées
- [ ] Tests unitaires 100%
- [x] Commit: `f0a6555` (entités créées)

### Feature 1.2 - Sessions Tracking
- [ ] `GET /sessions` - List sessions avec pagin
- [ ] `POST /sessions` - Ingestion Cowrie
- [ ] `GET /sessions/{id}/commands` - Historique commands
- [ ] Tests intégration

### Feature 1.3 - Commands Logging
- [ ] `POST /commands` - Log commands attaquant
- [ ] Classification auto (SQLi, XSS, brute force)
- [ ] Export JSON lines

---

## 🎯 Phase 2 : Scoring Engine (J+2)

### Feature 2.1 - Règles Config
- [ ] YAML config : scores par attack type
- [ ] Hot reload des règles
- [ ] Endpoint `GET /scoring/rules`

### Feature 2.2 - Classification Comportementale
- [ ] Timing analysis (latence, burst)
- [ ] Sequence analysis (patterns)
- [ ] `POST /classification`

---

## 🎯 Phase 3 : Integration Cowrie (J+3)

### Feature 3.1 - JSON Events
- [ ] Worker Cowrie → API
- [ ] Mapping Cowrie events vers Attack/Session
- [ ] Tests end-to-end

### Feature 3.2 - Docker Compose Full
- [ ] Cowrie container running
- [ ] Volume logs → worker
- [ ] Prometheus metrics

---

## 🎯 Phase 4 : Observabilité (J+4)

### Feature 4.1 - Prometheus Metrics
- [ ] Counter : attacks_by_type
- [ ] Histogram : session_duration
- [ ] Gauge : active_sessions

### Feature 4.2 - Grafana Dashboard
- [ ] JSON model dashboard
- [ ] Panels : Attacks, IPs, Timing
- [ ] Alerting rules (rate > 100/min)

---

## 📊 Progress Tracking

| Feature | Tests | Code | Commit | Done |
|---------|-------|------|--------|------|
| Core Entities | ✅ | ✅ | ✅ | ✅ |
| API Skeleton | ❌ | ✅ | ✅ | ❌ |
| Scoring | ❌ | ❌ | ❌ | ❌ |

## 🔄 Cadence Développement

- **Toutes les 30min** : Commit avec message clair
- **Chaque feature** : Tests obligatoires
- **Branch** : `feature/{nom-feature}` → merge PR
- **CI** : GitHub Actions (lint + tests)