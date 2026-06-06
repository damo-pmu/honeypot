# Architecture Decision Records

## ADR-001: Implementation Dashboard Analytics Page

**Date**: 2026-06-06

### Contexte
Le template `dashboard.html` référence une route `/dashboard/analytics` qui n'existait pas, retournant 404.

### Problème
Manque de route pour afficher les analytics du dashboard.

### Options étudiées
1. Utiliser Jinja2 templates existants (`/templates/dashboard.html`)
2. Implémenter f-string HTML inline dans le route handler

### Décision retenue
F-string HTML inline dans `dashboard_v3.py` pour rapidité et cohérence avec la route `/` existante.

### Justification
- La route `/` utilise déjà f-string HTML inline
- Template Jinja2 existe mais nécessite configuration supplémentaire
- Priorité à la fonctionnalité avant la perfection

### Impacts
- Code inline au lieu de template séparé
- Facile à refactoriser vers Jinja2 plus tard
- Fonctionnalité livrée rapidement