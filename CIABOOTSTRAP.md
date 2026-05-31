# CIABOOTSTRAP - Confidentialite & Isolation

> **NOTE : Ce fichier est versionné. Les données sensibles sont masquées.**

## 🔒 Principes de Confidentialité

- Aucun IP publique n'est exposé dans le code source
- Les logs sont caviardés avant publication
- Les secrets utilisent des variables d'environnement

## 📦 Structure du Projet

```
.env.ci          # Variables d'environnement - .gitignore
docker/          # Images Docker pour isolation
src/             # Code source versionné
```

## 🕐 Historique

- 2026-05-31: Architecture initiale publiée
- 2026-05-31: Authentification SSH configurée