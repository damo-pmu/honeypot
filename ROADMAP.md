# ROADMAP - Honeypot Threat Intelligence Framework

> **Méthode : Code → Test → Commit (30min cadences)**  
> **Security Rule : Never trust user input - whitelist + sanitization + local LLMs only**

---

## 🎯 Phase 1 : Core API Endpoints ✅

| Feature | Tests | Code | Commit | Done |
|---------|-------|------|--------|------|
| 1.1 Attackers CRUD | ✅ 5 | ✅ | ✅ | ✅ |
| 1.2 Sessions Tracking | ✅ 5 | ✅ | ✅ | ✅ |
| 1.3 Commands Logging | ✅ 4 | ✅ | ✅ | ✅ |

---

## 🎯 Phase 2 : Scoring Engine ✅

| Feature | Tests | Code | Commit | Done |
|---------|-------|------|--------|------|
| 2.1 Rules Engine | ✅ 7 | ✅ | ✅ | ✅ |
| 2.2 Behavior Classification | ✅ 6 | ✅ | ✅ | ✅ |

---

## 🎯 Phase 3 : Integration & IOC ✅

| Feature | Tests | Code | Commit | Done |
|---------|-------|------|--------|------|
| 3.1 Database Queries | ✅ 3 | ✅ | ✅ | ✅ |
| 3.2 GeoIP Enrichment | ✅ 4 | ✅ | ✅ | ✅ |
| 4.1 Docker/Cowrie | ✅ 0 | ✅ | ✅ | ✅ |
| 5.1 Prometheus Metrics | ✅ 3 | ✅ | ✅ | ✅ |
| 5.2 IOC Storage DB | ✅ 4 | ✅ | ✅ | ✅ |
| 5.3 IOC External Enrich | ✅ 11 | ✅ | ✅ | ✅ |
| 5.4 Redis Caching | ✅ 9 | ✅ | ✅ | ✅ |
| 7.1 Cowrie IOC Integration | ✅ 14 | ✅ | ✅ | ✅ |

---

## 🎯 Phase 4 : Response Engine ✅

| Feature | Tests | Code | Commit | Done |
|---------|-------|------|--------|------|
| 6.1 External IOC Feed | ✅ 11 | ✅ | ✅ | ✅ |
| 6.2 Redis Cache | ✅ 9 | ✅ | ✅ | ✅ |
| 8.1 Response Router | ✅ 16 | ✅ | ✅ | ✅ |
| 8.2 LLM Classifier | ✅ 8 | ✅ | ✅ | ✅ |
| 8.3 Security Hardening | ✅ 30 | ✅ | ✅ | ✅ |
| 10.1 LLM Provider Switching | ✅ 17 | ✅ | ✅ | ✅ |
| 10.2 Adversarial Prompts | ✅ 17 | ✅ | ✅ | ✅ |
| 9.1 Threat Intel Feeds | ✅ 5 | ✅ | ✅ | ✅ |

---

## 🛡️ Security Architecture Rules

1. **Never trust user input** - whitelist + pattern blocking
2. **LLMs locaux par défaut** - GPT4All/LlamaCpp (configurable)
3. **Templates statiques** - pas de génération dynamique de contenus
4. **Chroot/isolation** - pas de sortie réseau depuis le honeypot
5. **Audit trail complet** - timestamps sur toutes les tables

---

## 🔄 Development Cadence

- Toutes les 30min : Commit avec message clair
- Chaque feature : Tests obligatoires  
- Branch : `feature/{nom-feature}` → merge main
- CI : GitHub Actions (lint + tests)

---

## 📊 Totals

- **Commits:** 18
- **Tests:** 158
- **Features complètes:** 18/18