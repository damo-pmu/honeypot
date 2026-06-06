# Audit Report — Honeypot Threat Intelligence Framework

Date: 2026-06-06

## Scope
- Analyse statique des documents Markdown et du code Python dans le repo `honeypot/`.
- Vérification de la cohérence docs ↔ code, des risques de fuite de données, de la sécurité des endpoints, et des divergences opérationnelles (.env / docker).

## Executive Summary
- Globalement la documentation existe et couvre l'architecture et les APIs.
- Plusieurs incohérences fonctionnelles et risques de sécurité identifiés (templates, variables d'env, données factices contenant des secrets apparents, CORS permissif, bugs d'API potentiellement bloquants).

---

## Criticité élevée — à corriger immédiatement

1) Templates / Safety whitelist incohérentes
   - Observé: `router.py` référence `jenkins_instance/config` mais `fake_env.py` et la whitelist de `SafetyIsolator` utilisent `jenkins_ci/*`.
   - Fichiers: `src/response/router.py` (router template keys), `src/response/fake_env.py` (generators), `src/response/safety.py` (ALLOWED_TEMPLATES).
   - Risque: réponses bloquées par la whitelist ou templates non protégés → comportement imprévisible, risque d'exposition.
   - Recommandation: harmoniser les clés de template (choisir `jenkins_ci/*` ou `jenkins_instance/*`) et ajouter test automatisé qui valide que toute `template_name` retournée par les generators appartient à `ALLOWED_TEMPLATES`.

2) Decoys contenant des valeurs ressemblant à de vrais secrets
   - Observé: `fake_env.py` contient des chaînes ressemblant à mots de passe/connection strings/NTLM hashes (ex: `SuperSecret123!`, `Administrator:500:...`, `Old: admin123`, `New: Summer2024!`).
   - Fichiers: `src/response/fake_env.py`, `src/response/router.py` (some templates include `username admin privilege 15 secret ...`).
   - Risque: fuite accidentelle si logs/exports/analytics stockent ces sorties ou si un opérateur réutilise sans nettoyage.
   - Recommandation: remplacer par tokens explicites `FAKE_*` et documenter que toute donnée de decoy est factice; ajouter test qui vérifie l'absence de motifs de clés privées ou de tokens longs.

3) Incohérences API models → bug bloquant
   - Observé: `src/api/endpoints/sessions.py` `SessionCreate` n'expose pas `id`, mais `create_session` lit `session.id` (AttributeError possible). Voir `create_session`.
   - Observé: `src/api/endpoints/attackers.py` utilise `AttackerDB` keyed by `ip` mais retourne un `attacker_id` numérique obtenu par énumération; docs référencent `{attacker_id}` — incohérence d'identifiants.
   - Risque: endpoints POST/PUT peuvent échouer en runtime ou produire identifiants ambigus.
   - Recommandation: décider d'un modèle d'identifiant (préférer `session.id` fourni par le client OR généré serveur-side). Corriger `SessionCreate` pour inclure `id` si attendu, ou générer server-side et renvoyer. Pour `attackers`, utiliser `ip` comme identifiant unique (changer docs) ou ajouter un champ `id` dans DB.

---

## Criticité moyenne

4) Variables d'environnement / Docker mismatch
   - Observé: `.env.example` documente `API_KEY_OPENROUTER` mais `docker-compose.yml` expose `OPENROUTER_API_KEY=${API_KEY_OPENROUTER:-demo}` et tests reference `OPENROUTER_API_KEY`. Tests set `OPENROUTER_API_KEY` too. Il existe aussi `.env.local.example` using `API_KEY_OPENROUTER`.
   - Fichiers: `.env.example`, `.env.local.example`, `docker-compose.yml`, `tests/test_llm_provider.py`.
   - Risque: confusion opérationnelle, env keys non-resolues en déploiement.
   - Recommandation: standardiser sur `OPENROUTER_API_KEY` (ou `API_KEY_OPENROUTER`) dans tous les endroits et documenter clairement.

5) CORS permissif
   - Observé: `app.py` configure `CORSMiddleware` avec `allow_origins=["*"]`.
   - Risque: exposition inutile en production.
   - Recommandation: utiliser `ALLOWED_ORIGINS` env var et limiter à Grafana et frontends de confiance en production. Documenter le choix dans `docs/ARCHITECTURE.md`.

6) Patterns et couverture de `SafetyIsolator`
   - Observé: whitelist + blocked patterns existent mais regexes peuvent être trop larges ou incomplètes (ex: detection basée sur `[a-z]{32,}` peut causer faux positifs/negatifs).
   - Recommandation: renforcer avec tests unitaires, fournir liste négative/positive exhaustive, utiliser heuristiques supplémentaires (entropy check, token patterns), et logging d'events bloqués pour la revue.

---

## Criticité faible / observations diverses

- `AuditMiddleware` logge request/response et remote client info. Vérifier que les logs n'écrivent pas de corps sensibles (ex: password) — actuellement le middleware loggue `query` et `user_agent` mais pas le body.
- Plusieurs tests existent qui mockent variables d'environnement pour providers externes (VT, ABUSEIPDB, OpenRouter). Confirmer que `docs/APIS.md` indique clairement quelles features nécessitent clés externes.
- Rechercher et corriger usages potentiels d'`allow_origins=["*"]` dans d'autres déploiements.
- TODO markers détectés: `src/response/fake_env.py` contient `TODO: Change password before vacation` — nettoyer.

---

## Tests et validations recommandées (à ajouter au CI)

1. Test unitaire: toutes les clés `template_name` générées (via generators et `get_response_content`) doivent appartenir à `SafetyIsolator.ALLOWED_TEMPLATES` et passer `validate_response`.
2. Test d'intégration: POST `/sessions` simulate with and without `id` to confirm API behaviour; fix `SessionCreate` or server generation.
3. Test de non-régression: scanner pour motifs de secrets dans les réponses des endpoints (regex blocking) — échouer le build si trouvé.

---

## Plan d'actions proposées (ordonnés)

Phase 1 (immédiat)
- Harmoniser template keys (`jenkins_ci` vs `jenkins_instance`) et remplacer contenus sensibles par `FAKE_*` placeholders. (Code + tests)
- Corriger `create_session` / `SessionCreate` mismatch et choisir identifiant canonical pour `attackers` (ip vs id). (Code + docs)
- Standardiser env vars LLM (choix unique) et mettre à jour `.env.example` + `docker-compose.yml`.

Phase 2
- Restreindre CORS via env var et documenter.
- Renforcer `SafetyIsolator` et ajouter tests couvrant patterns bloquants.

Phase 3
- Ajouter tests CI (unit + integration) et exécuter scan secrets statique.
- Mettre à jour `docs/APIS.md` pour préciser paramètres, auth, et mapping fichier ↔ route.

---

## Artefacts ajoutés
- Ce rapport: `AUDIT_REPORT.md` (vous lisez actuellement).

---

Si vous confirmez, j'appliquerai automatiquement les corrections de Phase 1 (PR/patch) et j'ajouterai les tests recommandés. Préférez-vous que je: (A) applique automatiquement les corrections proposées, (B) génère un PR avec changements isolés pour revue, ou (C) continue l'audit plus en profondeur avant modifications ?
