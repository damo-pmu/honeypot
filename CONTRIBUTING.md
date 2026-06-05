# Contributing Guidelines

> Standards pour contributeurs - maintenabilité + sécurité

## Getting Started

```bash
# Clone + setup
git clone github-damo:damo-pmu/honeypot.git
cd honeypot
docker-compose up -d

# Tests
pytest tests/ -v
```

## Code Style

### Python
- **Format** : PEP8 + type hints obligatoires
- **Lint** : `ruff check src/`
- **Naming** :
  - `snake_case` : fonctions, variables
  - `PascalCase` : classes, Enums
  - `CONSTANTS` : valeurs immuables

### Documentation
- Alignée sur le code (`src/` → `docs/`)
- Format : Purpose → Implémentation → Tests → Limitations

---

## Development Flow

### Branches
```
main                    # Production
├── feature/nom-feature # Nouvelle fonctionnalité
├── fix/issue-name      # Bug fix
└── docs/update         # Documentation only
```

### Commits
```
feat: Add healthcheck filtering to cowrie ingest
fix: Correct session end_time null handling
docs: Update IOC queries documentation
test: Add test for dashboard stream SSE
refactor: Optimize queries with indexes
```

### Tests
- **Coverage** : >70% minimum pour nouveaux modules
- **Pattern** : `tests/test_{module}.py`
- **Run** : `pytest tests/test_{module}.py -v`

---

## Security Rules

### Input Validation
```python
# ❌ NEVER
db.execute(f"SELECT * FROM users WHERE ip='{user_input}'")

# ✅ ALWAYS
from sqlalchemy import text
safe_query = text("SELECT * FROM users WHERE ip=:ip").bindparams(ip=sanitized_ip)
```

### LLM Safety
1. **Templates statiques uniquement** - pas de génération dynamique
2. **Local LLMs** - GPT4All/LlamaCpp via `$LOCAL_LLM_MODEL`
3. **Sanitisation** - suppression `{}` dans prompts
4. **Fallback rules** - si LLM indisponible

### Response Templates
- Stocker dans `src/response/templates/` en prod
- Validation whitelist des templates
- Pas de données sensibles dans templates

---

## Pull Request Workflow

1. **Branch** depuis `main`
   ```bash
   git checkout -b feature/nouvelle-fonction
   ```

2. **Tests + Lint**
   ```bash
   pytest tests/
   ruff check src/
   ```

3. **Commit clean**
   - No unstaged files
   - Conventional Commits format

4. **Review**
   - Security check obligatoire
   - Coverage minimum 70%

5. **Merge**
   - Squash + merge via GitHub

---

## Architecture Decisions

### Patterns
- **Event-driven** : Worker polling logs JSON
- **CQRS** : endpoints /internal vs /dashboard/public
- **Repository** : queries séparées (`src/infrastructure/database/`)

### Database
- Toutes tables avec `created_at` timestamp
- FK cascade `ondelete="CASCADE"`
- Indexes composites pour queries multi-colonnes

---

## Matrice Documentation

| Type | Source | Docs |
|------|--------|------|
| Endpoints | `src/api/endpoints/*.py` | `docs/APIS.md` |
| Services | `src/services/*.py` | `docs/SERVICES.md` |
| Workers | `src/workers/*.py` | `docs/WORKERS.md` |
| DB models | `src/core/database.py` | `docs/DATA_MODEL.md` |
| Queries | `src/infrastructure/database/queries.py` | `docs/QUERIES.md` |
| Scoring | `src/scoring/engine.py` | `docs/SCORING.md` |

---

## Issues & Roadmap

- **Bugs** : Issue avec reproduction steps
- **Features** : Aligner sur `/ROADMAP_ANALYSIS.md`
- **Security** : `Security` label prioritaire

---

## License

MIT - Usage défensif uniquement