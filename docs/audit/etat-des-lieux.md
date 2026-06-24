# État des lieux - Audit du dépôt Honeypot

Date: 2026-06-24  
Sous-tâche: HON-3  
Auteur: damo_pmu (agent backend)

---

## 1. Structure du dépôt

```
honeypot/
├── .hermes/           # Configuration Hermes (agents, skills)
├── docker/            # Dockerfiles par service (api, worker, seed)
├── docker-compose.yml # Orchestration complète (199 lignes - see risques)
├── grafana/           # Provisioning Grafana (datasources, dashboards)
├── migrations/        # Migrations SQLAlchemy (à vérifier)
├── scripts/           # Scripts maintenance, injection, seed
├── src/
│   ├── analytics/     # Queries SQL + analytics API
│   ├── api/           # Routers FastAPI (endpoints + middleware)
│   ├── core/          # Entités DB, config
│   ├── detection/     # Détection comportementale
│   ├── infrastructure/# GeoIP, enrichment, observability, feeds
│   ├── messaging/     # RabbitMQ/Redis
│   ├── repositories/  # Accès DB (pattern repository)
│   ├── response/      # Response engine, safety, fake_env, LLM
│   ├── scoring/       # Scoring engine
│   ├── services/      # Business logic (IOC, MITRE, campaign)
│   ├── static/        # CSS/JS dashboard
│   ├── templates/     # HTML templates Jinja2
│   └── workers/       # Cowrie ingestion, producers
├── tests/             # Tests Pytest (25 fichiers)
└── docs/              # Documentation publique
    ├── ARCHITECTURE.md
    ├── APIS.md
    ├── DATA_MODEL.md
    └── ...
```

## 2. Dépendances (`requirements.txt`)

| Package | Version | Status |
|---------|---------|--------|
| fastapi | >=0.100.0 | ✅ Maintenu |
| uvicorn | >=0.29.0 | ✅ Maintenu |
| pydantic | >=2.6.0 | ✅ Maintenu |
| sqlalchemy | >=2.0.0 | ✅ Maintenu |
| psycopg2-binary | >=2.9.0 | ✅ Maintenu |
| structlog | >=24.1.0 | ⚠️ Version récente |
| prometheus-client | >=0.20.0 | ✅ Maintenu |
| opentelemetry-sdk | >=1.25.0 | ✅ Maintenu |
| redis | >=5.0.0 | ✅ Maintenu |
| aio-pika | >=9.2.0 | ✅ Maintenu |
| aiohttp | >=3.9.0 | ✅ Maintenu |
| requests | >=2.31.0 | ✅ Maintenu |
| httpx | >=0.27.0 | ✅ Maintenu |
| langchain | >=0.3.0 | ⚠️ Lourd, usage limité |
| jinja2 | >=3.1.0 | ✅ Maintenu |
| geoip2 | >=5.0.0 | ✅ Maintenu |

**Observation**: Aucune dépendance obsolète majeure détectée. `langchain` semble utilisé uniquement pour la classification LLM.

## 3. Risques identifiés

### 3.1 ❌ Critique - Bug infrastructure (docker-compose.yml)

**Fichier**: `docker-compose.yml:109`

```yaml
# LIGNE 109 - ERREUR DE SYNTAXE
- REDIS_URL=redis://${REDIS_HOST:***@${DB_HOST:-postgres}:${DB_PORT:-5432}/${DB_NAME:-honeypot}
```

**Problème**: Syntaxe invalide - `${REDIS_HOST:***@...` mélange Redis et PostgreSQL.  
**Impact**: Le service `rabbitmq-consumer` démarrera avec une URL Redis incorrecte.  
**Correction**: `redis://${REDIS_HOST:-redis}:${REDIS_PORT:-6379}`

### 3.2 ⚠️ Moyen - Incompatibilité template names

**Fichiers**: `src/response/router.py`, `src/response/safety.py`, `src/response/fake_env.py`

| Template name dans `router.py` | Présent dans `ALLOWED_TEMPLATES` (safety.py) |
|-------------------------------|---------------------------------------------|
| cisco_router/show_version     | ✅ Oui (via template_name cisco_router) |
| jenkins_ci/config             | ✅ Oui |
| windows_server/credentials    | ✅ Oui |
| ai_challenge/cognitive_trap   | ❌ NON - manquant dans whitelist |

**Problème**: Le template `ai_challenge/cognitive_trap` n'est pas dans la whitelist `ALLOWED_TEMPLATES`.  
**Impact**: Risque d'être bloqué par `SafetyIsolator.validate_response()`.  
**Recommandation**: Ajouter `ai_challenge/*` ou `ai_challenge/cognitive_trap` à la whitelist.

### 3.3 ⚠️ Moyen - Credentials factices dans décoy

**Fichier**: `src/response/fake_env.py:147-152`

```python
SAFE_CREDENTIALS = [
    "admin:Password123!",          # ⚠️ Mot de passe "realiste"
    "root:toor",
    "user:changeme",
    "Administrator:Summer2024!",   # ⚠️ Mot de passe "realiste"
    "backup:B@ckupKey2024"
]
```

**Problème**: Ces valeurs ressemblent à de vrais mots de passe et pourraient être réutilisées par erreur.  
**Impact**: Risque de fuite si logs/analytics exportent ces données.  
**Recommandation**: Remplacer par `FAKE_*` explicites ET ajouter test anti-pattern.

### 3.4 ⚠️ Moyen - Attacker ID incohérent

**Fichier**: `src/api/endpoints/attackers.py:77`

```python
attacker_id = next((i+1 for i, a in enumerate(attackers) if a.ip == db_attacker.ip), 1)
```

**Problème**: L'ID n'est pas stocké en DB, il est calculé par énumération.  
**Impact**: Identifiants instables lors de suppressions/ajouts.  
**Note**: La DB utilise `ip` comme PK (`AttackerDB`), le modèle `Attacker` expose un `id` numérique.

### 3.5 ⚠️ Faible - CORS (rapporté dans AUDIT_REPORT.md)

**Fichier**: `app.py:33-52` - CORRECTEMENT CORRIGE

Le CORS utilise maintenant `CORS_ALLOWED_ORIGINS` depuis `.env.example`.  
Aucun `allow_origins=["*"]` actuel - correction déjà appliquée.

### 3.6 ⚠️ Faible - Variables d'environnement incohérentes

**Incohérence**: `.env.local.example` utilise `API_KEY_OPENROUTER` alors que `.env.example` et le code utilisent `OPENROUTER_API_KEY`.

## 4. État des tests

| Fichier | Lines | Couverture estimée |
|---------|-------|-------------------|
| test_audit_fixes_phase1.py | 180 | Tests sécurité |
| test_audit_fixes_phase2.py | 326 | Tests intégration |
| test_audit_fixes_phase3.py | 363 | Tests sécurité avancés |
| test_response_security.py | 130 | SafetyIsolator |
| test_response_engine.py | 107 | Router decoy |

**Observations**:
- 22 fichiers de tests détectés
- Présence de tests pour les corrections d'audit (Phase 1-3 déjà prévues)
- Tests mockent variables d'environnement externes (VT, ABUSEIPDB, OpenRouter)
- Fixtures de test dans `conftest.py` non analysées en détail

## 5. Documentation vs Réalité

| Document | Présence | Alignement |
|----------|----------|------------|
| README.md | ✅ | Mentionne `/attackers`, `/sessions`, `/commands`, `/analytics/*` - API existent |
| ARCHITECTURE.md | ✅ | Décrit Docker + workers - cohérent avec docker-compose.yml |
| APIS.md | ✅ | Endpoints documentés - à vérifier avec implémentation |
| DATA_MODEL.md | ✅ | Schéma DB décrit - correspond à models SQLAlchemy |
| HANDOVER.md | ✅ | Guide de reprise complet |

**Écarts mineurs**:
- README.md mentionne `docs/audit/etat-des-lieux.md` mais le dossier n'existe pas encore
- `docs/SCORING.md` référence `RiskEngine` mais le module s'appelle `risk_engine.py`

## 6. Code mort / duplication

| Emplacement | Statut |
|-------------|--------|
| `src/static/` | Templates frontend - nécessaire pour dashboard |
| `src/utils/` | Fichiers utilitaires - à vérifier |
| `scripts/` | Scripts maintenance/seed - utilisés |

## 7. Priorisation (impact × effort)

| Priorité | Action | Fichier | Effort |
|----------|--------|---------|--------|
| 🔴 CRITIQUE | Corriger REDIS_URL dans docker-compose.yml | docker-compose.yml:109 | 5 min |
| 🟡 HAUTE | Ajouter `ai_challenge/*` à ALLOWED_TEMPLATES | safety.py | 10 min |
| 🟡 HAUTE | Harmoniser SAFE_CREDENTIALS avec préfixe FAKE_ | fake_env.py | 15 min |
| 🟡 MOYENNE | Standardiser `OPENROUTER_API_KEY` env var | .env.local.example | 5 min |
| 🟢 BASSE | Documenter écarts README/docs | README.md | 30 min |

## 8. Checklist de validation

- [x] Structure analysée (10 dossiers principaux dans src/)
- [x] Dépendances listées et vérifiées
- [x] Risques critiques identifiés
- [x] État des tests documenté
- [x] Incohérences docs/code relevées
- [ ] Tests locaux à exécuter (lint + pytest)

---

## 9. Prochaine étape

Ce rapport est `docs/audit/etat-des-lieux.md`. Aucune modification de code n'a été apportée (conformément à la tâche).

Pour passer en `In Review` :
1. Vérifier que le report est complet
2. Les corrections critiques (section 3.1) devraient être traitées dans une sous-tâche dédiée