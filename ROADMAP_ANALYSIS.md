# Roadmap d'Analyse Fonctionnelle - Honeypot SOC

> Analyse code-first : chaque fonctionnalité documentée est liée à son implémentation réelle

## Phase 1 : Infrastructure (3 tâches)

| Tâche | Code source | Output documentation |
|-------|-------------|---------------------|
| 1.1 Architecture Docker | `docker-compose.yml` | `docs/ARCHITECTURE.md` |
| 1.2 Modèle données | `src/core/entities/models.py` + `src/core/database.py` | `docs/DATA_MODEL.md` |
| 1.3 Configuration DB | `src/core/database.py` | `docs/DATABASE.md` |

## Phase 2 : API Endpoints (10 modules)

| Tâche | Code source | Output documentation |
|-------|-------------|---------------------|
| 2.1 Attackers API | `src/api/endpoints/attackers.py` | `docs/API_ATTACKERS.md` |
| 2.2 Sessions API | `src/api/endpoints/sessions.py` | `docs/API_SESSIONS.md` |
| 2.3 Commands API | `src/api/endpoints/commands.py` | `docs/API_COMMANDS.md` |
| 2.4 Behavior API | `src/api/endpoints/behavior.py` | `docs/API_BEHAVIOR.md` |
| 2.5 Analytics API | `src/api/endpoints/analytics.py` | `docs/API_ANALYTICS.md` |
| 2.6 Enrichment API | `src/api/endpoints/enrichment.py` | `docs/API_ENRICHMENT.md` |
| 2.7 IOC API | `src/api/endpoints/ioc.py` + `src/infrastructure/observability/metrics.py` | `docs/API_IOC.md` |
| 2.8 Response API | `src/api/endpoints/response.py` + `src/response/router.py` | `docs/API_RESPONSE.md` |
| 2.9 Dashboard API | `src/api/endpoints/dashboard.py` | `docs/API_DASHBOARD.md` |
| 2.10 Attacks API | `src/api/endpoints/attacks.py` | `docs/API_ATTACKS.md` |

## Phase 3 : Services métiers (10 services)

| Tâche | Code source | Output documentation |
|-------|-------------|---------------------|
| 3.1 Attacker Profiler | `src/services/attacker_profiler.py` | `docs/SERVICES_PROFILER.md` |
| 3.2 Behavior Analyzer | `src/services/behavior_analyzer.py` + `src/response/llm_classifier.py` | `docs/SERVICES_BEHAVIOR.md` |
| 3.3 Campaign Engine | `src/services/campaign_engine.py` | `docs/SERVICES_CAMPAIGN.md` |
| 3.4 Correlation Engine | `src/services/correlation_engine.py` | `docs/SERVICES_CORRELATION.md` |
| 3.5 IOC Extractor | `src/services/ioc_extractor.py` | `docs/SERVICES_IOC.md` |
| 3.6 MITRE Mapper | `src/services/mitre_mapper.py` | `docs/SERVICES_MITRE.md` |
| 3.7 Replay Service | `src/services/replay_service.py` | `docs/SERVICES_REPLAY.md` |
| 3.8 Risk Engine | `src/services/risk_engine.py` | `docs/SERVICES_RISK.md` |
| 3.9 Statistics Service | `src/services/statistics_service.py` | `docs/SERVICES_STATS.md` |
| 3.10 Threat Intel Service | `src/services/threat_intel_service.py` | `docs/SERVICES_THREATINTEL.md` |

## Phase 4 : Intégration Cowrie & Workers (3 tâches)

| Tâche | Code source | Output documentation |
|-------|-------------|---------------------|
| 4.1 Cowrie Ingest | `src/workers/cowrie_ingest.py` | `docs/WORKER_COWRIE.md` |
| 4.2 Métriques | `src/infrastructure/observability/metrics.py` | `docs/OBSERVABILITY.md` |
| 4.3 Response Router | `src/response/router.py` + `src/response/fake_env.py` | `docs/RESPONSE_ENGINE.md` |

## Phase 5 : Documentation consolidée (2 tâches)

| Tâche | Output |
|-------|--------|
| 5.1 Matrice features | `docs/FEATURES_MATRIX.md` (couverture code/test) |
| 5.2 Rapport final | `docs/ANALYSIS_REPORT.md` (résumé + recommandations) |

---

## Code de conduite & Guidelines contributeurs

### Code style
- **Python** : PEP8, type hints obligatoires, docstrings pour fonctions publiques
- **Naming** : snake_case pour fonctions/variables, PascalCase pour classes
- **Tests** : pytest, chaque feature = 0 minimum test, coverage >70%
- **Commits** : Conventional Commits (feat:, fix:, docs:, refactor:)

### Sécurité first
1. Toute entrée utilisateur → validation whitelist
2. LLMs locaux uniquement (GPT4All/LlamaCpp)
3. Templates statiques pour responses
4. Never trust external input - sanitize before DB

### Structure commits
```
feat: <description>     # Nouvelle fonctionnalité
fix: <description>      # Bug fix
docs: <description>     # Documentation only
refactor: <description> # Modif code sans changement comportement
test: <description>     # Ajout tests
chore: <description>    # Maintenance
```

### Pull Request flow
1. Branch `feature/nom-feature` depuis `main`
2. Tests obligatoires + linting (`ruff check src/`)
3. Review + approbation requise
4. Merge via squash

---

## Matrice produit ↔ technique

| User Story | Endpoints implémentés | Tables concernées | Services |
|------------|---------------------|-------------------|----------|
| Qui attaque ? | `/attackers`, `/enrichment/ip` | `attackers`, `sessions` | profiler, threat_intel |
| Comment attaque ? | `/sessions`, `/commands`, `/dashboard/api/sessions` | `sessions`, `commands`, `attacks` | analyzer, replay |
| Quelles actions ? | `/commands`, `/ioc`, `/analytics` | `commands`, `ioc_indicators`, `attacks` | ioc_extractor, mitre |
| Réponse adaptative | `/response`, `/dashboard/stream` | `sessions`, `attacks` | router, fake_env |

---

## Expertise produit (Product Owner)

### Fonctionnalités par user story
1. **Attaquant·e·s** - Qui attaque ?
   - Enregistrement IP avec géoloc
   - Classification (BOT, HUMAN, SCRIPT_KIDDIE)
   - Scoring menace temps réel

2. **Sessions** - Comment attaque-t-on ?
   - Démarrage/fermeture session
   - Durée + interaction count
   - Timeline chronologique

3. **Commands** - Quelles actions ?
   - Logging commandes exécutées
   - Flagging comportement malveillant
   - Extraction IOCs inline

4. **Réponse dynamique** - Que faire ?
   - Déploiement decoy adaptatif
   - Challenge pour AI agents
   - Termination après seuils

### Workflows métiers
- Brute force detection → Classification → Score
- Malware download → IOC extraction → Threat intel enrich
- Unknown attacker → Fake env router → Session logging

## Expertise technique (Architecte/SRE)

### Architecture technique
- **Pattern** : Event-driven + CQRS (sessions/events séparés)
- **DB schema** : Relations explicites avec FK cascade
- **Indexations** : attacker_ip, session_id, timestamp
- **Security** : Sanitisation input, templates statiques, LLM local-only

**Format documentation :**
```markdown
# Fonctionnalité

## Code source
- Fichier principal
- Lignes clés

## Purpose
Description concise

## Implémentation
- Logique principale
- Endpoints/Tables concernées

## Tests
- Fichier test associé
- Coverage actuelle

## Limitations/Stalemates
Points à attention
```

---

## Priorités de traitement

1. **Bloc 1 critique** : Infrastructure + API core (attackers, sessions, commands)
2. **Bloc 2** : Detection (behavior, ioc, response)
3. **Bloc 3** : Services avancés (threat intel, mitre, campaign)
4. **Bloc 4** : Consolidation

**Durée estimée** : 4-6 heures de travail (analyse approfondie)