# Technical Debt

## Dette identifiée

### TECH-001: F-string HTML au lieu de Jinja2
- **Description**: Routes dashboard utilisent f-string HTML inline au lieu de templates Jinja2
- **Impact**: Maintenabilité réduite, duplication potentielle
- **Criticité**: LOW
- **Plan de résolution**: Refactoriser vers `/templates/dashboard.html` et `/templates/dashboard_analytics.html`

### TECH-002: Unused imports
- **Description**: `hashlib` importé mais non utilisé dans `src/analytics/ioc_scanner.py`
- **Impact**: Warning ruff
- **Criticité**: LOW
- **Plan de résolution**: Supprimer l'import

### TECH-003: datetime.utcnow() deprecated
- **Description**: Usage de `datetime.utcnow()` au lieu de `datetime.now(timezone.utc)`
- **Impact**: Deprecation warning Python 3.12+
- **Criticité**: MEDIUM
- **Plan de résolution**: Remplacer toutes les occurrences

### TECH-004: Settings route manquante
- **Description**: `/dashboard/settings` référencé mais non implémenté
- **Impact**: Lien cassé dans le dashboard
- **Criticité**: MEDIUM
- **Plan de résolution**: Implémenter la route ou retirer le lien