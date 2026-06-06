# Changelog — phase3-work vs master

Ce document résume les changements principaux apportés sur la branche `phase3-work` par rapport à `master`, afin qu'un développeur puisse comprendre l'état actuel du projet et reprendre proprement avec la documentation de handover.

## Résumé global

La branche `phase3-work` apporte une refonte complète du dashboard vers une architecture FastAPI + Jinja2 template-based, avec :

- Dashboard production-ready (`dashboard_v3`) intégré dans `app.py`
- Authentification session cookie sécurisée pour l'interface dashboard
- API analytics expertes et exports structurés
- Flux temps réel WebSocket avec fallback HTTP
- Sécurité renforcée CORS et audit logging
- Documentation mise à jour (`docs/APIS.md`, `docs/ARCHITECTURE.md`, `docs/HANDOVER.md`)
- Suite de tests complète pour Phase 2 et Phase 3

## Changements clés

### Dashboard
- Ajout de `src/api/endpoints/dashboard_v3.py` pour remplacer l'ancien router `src/api/endpoints/dashboard.py`.
- Nouvelle interface Jinja2 avec `src/templates/base.html`, `dashboard.html`, `dashboard_login.html`.
- Static assets modernes : `src/static/css/dashboard.css` et `src/static/js/dashboard.js`.
- Routes UI : `/dashboard/`, `/dashboard/login`, `/dashboard/logout`.
- API dashboard : `/dashboard/api/stats`, `/dashboard/api/live-feed`, `/dashboard/api/analytics/*`, `/dashboard/api/export/*`, `/dashboard/api/search/*`, `/dashboard/api/meta/endpoints`, `/dashboard/api/health`.
- WebSocket live feed protégé : `/dashboard/ws/live`.
- Cookie de session `dash_session` utilisé pour l’authentification dashboard.

### Services & analytics
- Ajout de `src/services/dashboard_analytics_service.py` pour les fonctionnalités analytics avancées.
- Mise en place d’un export JSON/CSV via `DashboardExportService`.
- Intégration de `StatisticsService` pour les stats dashboard.

### Sécurité et configuration
- Renforcement de la politique CORS via `CORS_ALLOWED_ORIGINS`.
- Implémentation de enhancements SafetyIsolator pour détection de secrets.
- Standardisation des variables LLM (`OPENROUTER_API_KEY`).
- Gestion des sessions via `src/api/middleware/session.py`.

### Documentation
- Mise à jour de `docs/APIS.md` pour refléter le dashboard v3 actuel.
- Correction de `docs/ARCHITECTURE.md` pour supprimer SSE et documenter le WebSocket / fallback HTTP.
- Ajout et enrichissement de `docs/HANDOVER.md` pour le contexte de reprise.
- Mise à jour de `README.md` pour le mode live réel.

### Tests
- Ajout de `tests/test_audit_fixes_phase3.py` pour la validation dashboard Phase 3.
- Ajout de `tests/test_audit_fixes_phase2.py` pour la sécurité CORS et audit.
- Renforcement des tests d’enrichissement, LLM et sessions.

### Nettoyage
- Suppression de l’ancien routeur dashboard legacy (`src/api/endpoints/dashboard.py`).
- Suppression des templates obsolètes `src/templates/dashboard_v2.html` et `src/templates/login.html`.

## Historique des commits

- `ce4ef34` docs(handover): Add branch info and deployment instructions for phase3-work
- `9cad102` docs: add Phase 3 handover and audit artifacts in dedicated branch
- `4e8c0e0` test(dashboard): Add comprehensive Phase 3 dashboard API validation suite
- `b64bc3f` build(app): Integrate dashboard v3 router with production-ready API
- `f0ac982` feat(api): Implement production-ready dashboard API v3 with expert features
- `5584da9` feat(dashboard): Add comprehensive analytics service for expert SOC dashboard
- `9f33518` test: Add comprehensive Phase 2 security audit test suite
- `dbc28bb` config: Add CORS_ALLOWED_ORIGINS to environment and deployment configuration
- `ec0f344` docs: Document CORS policy and security configuration in ARCHITECTURE.md
- `3722ea7` feat(security): Enhance SafetyIsolator with comprehensive secret detection patterns
- `fbae368` feat(security): Implement CORS restriction with configurable origins
- `2b89913` test: Add comprehensive audit fixes validation test suite
- `7376b5c` fix: Standardize LLM environment variable names to OPENROUTER_API_KEY
- `286ca9c` fix: Refine SafetyIsolator blocked patterns to avoid false positives
- `328902b` fix: Add id field to SessionCreate model for UUID handling
- `71e5779` fix: Replace secret-like literals in decoys with FAKE_* markers
- `be84180` fix: Unify template keys (jenkins_instance → jenkins_ci)

## État actuel pour reprise

- Branche : `phase3-work`
- Objectif : Dashboard production-ready avec UI Jinja2 et APIs expertes.
- Attention : `.env.example` et `docker-compose.yml` ont été modifiés pour CORS/auth.
- Documentation principale pour reprise : `docs/HANDOVER.md`, `docs/CHANGELOG.md`, `docs/APIS.md`, `docs/ARCHITECTURE.md`.
- Tests recommandés : `pytest tests/test_audit_fixes_phase2.py tests/test_audit_fixes_phase3.py`.
