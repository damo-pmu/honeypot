# Architecture Analysis - Honeypot Phase 3

## Architecture Actuelle

### Structure du projet
```
src/
├── api/
│   ├── endpoints/
│   │   ├── dashboard_v3.py    # Dashboard routes (inline HTML)
│   │   ├── attackers.py
│   │   ├── sessions.py
│   │   ├── commands.py
│   │   ├── analytics.py
│   │   ├── ioc.py
│   │   └── ...
│   └── middleware/
│       ├── audit.py           # Security audit logging
│       └── session.py         # Session management
├── services/
│   ├── dashboard_analytics_service.py
│   ├── statistics_service.py
│   └── ...
├── repositories/
│   └── statistics_repository.py
├── core/
│   └── database.py            # SQLAlchemy models
└── static/
    ├── css/
    └── js/
templates/
├── base.html
├── dashboard.html             # Jinja2 template EXISTANT mais non utilisé
└── dashboard_login.html
```

### Patterns identifiés
- **FastAPI + SQLAlchemy** : Routes avec `Depends(get_db)`
- **Service Layer** : `StatisticsService`, `DashboardAnalyticsService`
- **Repository Pattern** : `StatisticsRepository`
- **Pydantic Models** : Validation des données
- **JWT/Session Auth** : Cookie `dash_session` HttpOnly

### Violations identifiées

#### 1. Architecture modulaire (CRITIQUE)
- `/dashboard/` et `/dashboard/analytics` utilisent f-string HTML au lieu de templates Jinja2
- Template `templates/dashboard.html` existant mais non exploité
- Template `templates/dashboard_login.html` existant

#### 2. Violation séparation responsabilités
- HTML/CSS/JS inline dans les routes Python
- Logique d'affichage mélangée au code backend

#### 3. Points faibles
- Pas de `/dashboard/settings` implémenté (link cassé)
- Auth WebSocket non implémentée
- Pas de rate limiting
- Pas de RBAC avancé

### Dette technique
1. `datetime.utcnow()` → `datetime.now(timezone.utc)` (deprecated)
2. Variables d'environnement non documentées dans `.env.example`
3. Templates Jinja2 existants non utilisés
4. Code inline HTML non maintenable

## Architecture Cible

### Refactoring dashboard
```
src/api/endpoints/dashboard_v3.py
- dashboard_home() → utilise TemplateResponse('dashboard.html')
- analytics_page() → utilise TemplateResponse('dashboard_analytics.html')  
- settings_page() → utilise TemplateResponse('dashboard_settings.html')
```

### Templates à créer
- `templates/dashboard_analytics.html` - Analytics page
- `templates/dashboard_settings.html` - Settings (placeholder)

### Améliorations
1. Externaliser CSS/JS dans `static/`
2. Utiliser Jinja2 pour la séparation
3. Auth améliorée avec WebSocket
4. RBAC basique (admin/analyst/viewer)

## Plan d'évolution
1. ✅ Routes fonctionnelles (complétées)
2. 🔄 Refactor Jinja2 templates (en cours)
3. 🔜 Settings route
4. 🔜 Documentation complète
5. 🔜 Tests pytest