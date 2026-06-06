# Contribuer — Guide professionnel

Ce document définit les règles et la checklist requises pour contribuer au projet Honeypot. Il vise à rendre les contributions sûres, testables et immédiatement exploitables en production.

## Table des matières
- Objectif
- Démarrage rapide
- Validation automatique (exigée)
- Style, linting et tests
- Workflow Git & PR
- Sécurité et secrets
- Documentation & handover
- Checklist de revue

## Objectif
Permettre des contributions reproductibles, auditées et faciles à reprendre par un ingénieur ou un agent automatisé. Toute PR doit contenir les éléments nécessaires à la validation et au rollback.

## Démarrage rapide
1. Cloner le dépôt et se placer dans le répertoire :
```bash
git clone <REPO_URL>
cd honeypot
```
2. Vérifier l'environnement et générer `.env` (dry-run) :
```bash
./scripts/setup.sh --dry-run
# si disponible: ./scripts/setup.sh --skip-docker
```
3. Démarrer localement si nécessaire :
```bash
docker compose up -d --build
```

## Validation automatique (exigée avant PR)
Avant d'ouvrir une PR, exécutez et corrigez les éléments suivants :
- `./scripts/setup.sh --dry-run` (doit réussir)
- `ruff check src/` (linting)
- `pytest tests/ -q` (tests unitaires)
- Vérifier la présence et la cohérence des documents : `CONTRIBUTING.md`, `docs/HANDOVER.md`, `docs/CHANGELOG.md`, `README.md`.

Commandes conseillées :
```bash
./scripts/setup.sh --dry-run
ruff check src/
pytest tests/ -q
# vérifier changements non désirés (secrets)
git diff --staged | grep -iE "(PASSWORD|KEY|SECRET|TOKEN)" || true
```

### Pre-commit (requis pour qualité continue)
Nous utilisons `pre-commit` pour appliquer automatiquement le formatting, le tri d'import, et les vérifications avant commit/push. Installez et activez-le ainsi :

```bash
python -m pip install --user pre-commit
pre-commit install           # active les hooks au commit
pre-commit install --hook-type pre-push  # active also the pre-push hook (pytest)
pre-commit run --all-files   # appliquer les hooks à tous les fichiers
```

Fichier de configuration : `.pre-commit-config.yaml` (contenu ajouté au dépôt). Le pipeline effectue :
- `black` (formatage)
- `isort` (tri des imports)
- `ruff --fix` (lint & correctifs automatiques)
- vérifications générales (`end-of-file-fixer`, `trailing-whitespace`, `check-yaml`, `check-merge-conflict`)
- `pytest` en hook `pre-push` (exécute la suite de tests lors du push)

Remarques :
- Le hook `pytest` en pre-push peut ralentir les pushes ; si tu veux l'activer seulement sur CI, ne l'active pas localement.
- Si un hook corrige des fichiers (black, isort, ruff), re-stagez les modifications avant de re-committer.

## Style, linting et tests
- Respecter PEP8 et ajouter des annotations de types sur les signatures publiques.
- Utiliser `ruff` pour linting/formatage. Optionnel : `mypy` pour vérification stricte.
- Tests : isoler la logique pure et mocker les effets de bord. Pattern : `tests/test_{module}.py`.
- Objectif couverture : 70%+ pour les nouveaux modules, mais priorité à la qualité des tests.

## Workflow Git & Pull Requests
- Branching :
   - `main` — production stable
   - `feature/<nom>` — nouvelles fonctionnalités
   - `fix/<nom>` — corrections
   - `docs/<nom>` — documentation
- Commits : suivre Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
- PR : inclure description, rollback plan si impact, checklist de validation.
- Merge : privilégier `Squash and merge` pour garder un historique clair.

## Sécurité et gestion des secrets
- Ne pas committer de secrets. Utiliser variables d'environnement et `./scripts/setup.sh`.
- Toute modification de la surface d'authentification ou de CORS exige un passage explicite dans `docs/HANDOVER.md`.
- Les PRs changeant la configuration réseau ou les règles d'accès doivent inclure un plan de sécurité et des tests d'intrusion simples.

## Documentation & Handover
- Mettre à jour systématiquement : `docs/APIS.md`, `docs/ARCHITECTURE.md`, `docs/HANDOVER.md`, `docs/CHANGELOG.md`.
- `docs/HANDOVER.md` doit indiquer : procédure de déploiement, variables d'environnement critiques, accès (qui), rollback.

## Checklist de revue (exigée)
- [ ] `./scripts/setup.sh --dry-run` : OK
- [ ] Lint : `ruff` — OK
- [ ] Tests : `pytest` — OK
- [ ] Pas de secrets dans le diff
- [ ] Documentation pertinente mise à jour
- [ ] Migration DB (si applicable) fournie dans `migrations/`
- [ ] Plan de rollback/impact listé

## Signaler un bug ou demander une amélioration
- Ouvrir une issue avec reproduction, logs, et impact.
- Pour incidents production, suivre la procédure de `docs/HANDOVER.md` (contacts, niveau d'urgence).

---

Si tu veux, je peux committer cette version et ouvrir une PR automatiquement. Veux-tu que je le fasse ?

