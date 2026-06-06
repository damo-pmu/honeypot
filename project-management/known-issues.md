# Known Issues

## ISSUE-001: Tests pytest bloqués
- **Description**: `ModuleNotFoundError: No module named 'sqlalchemy'` lors de l'exécution des tests
- **Impact**: Impossible de valider les tests unitaires automatisés
- **Contournement**: Tests manuels avec curl validés
- **Statut**: OPEN

## ISSUE-002: /dashboard/settings 404
- **Description**: Le lien "Settings" dans le dashboard pointe vers `/dashboard/settings` qui retourne 404
- **Impact**: UX - Lien cassé
- **Contournement**: Aucun
- **Statut**: TODO