# Backlog - Honeypot Phase 3

## Items

### PROJ-001: Dashboard Analytics Page
- **Description**: Implémenter la route `/dashboard/analytics` manquante
- **Priorité**: HIGH
- **Statut**: DONE
- **Dépendances**: StatisticsRepository, DashboardAnalyticsService
- **Estimation**: 1h

### PROJ-002: Dashboard Settings Page
- **Description**: Implémenter la route `/dashboard/settings` manquante (référencée dans le template)
- **Priorité**: MEDIUM
- **Statut**: TODO
- **Dépendances**: Aucune
- **Estimation**: 30min

### PROJ-003: Documentation API
- **Description**: Mettre à jour `docs/APIS.md` avec les nouveaux endpoints dashboard
- **Priorité**: HIGH
- **Statut**: TODO
- **Dépendances**: PROJ-001
- **Estimation**: 30min

### PROJ-004: Tests Unitaires
- **Description**: Exécuter la suite complète pytest sur le projet
- **Priorité**: HIGH
- **Statut**: BLOCKED (venv requis)
- **Dépendances**: Aucune
- **Estimation**: 1h

### PROJ-005: Nettoyage Imports
- **Description**: Supprimer `hashlib` unused dans `ioc_scanner.py`
- **Priorité**: LOW
- **Statut**: TODO
- **Dépendances**: Aucune
- **Estimation**: 5min