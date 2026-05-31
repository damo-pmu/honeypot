# Dashboard Architecture Plan - Modern & User-Friendly

## Objectif
Dashboard temps réel, user-friendly, auth minimale intégré à docker-compose

## Architecture cible
```
User → dashboard.hiddenlabs.cc:80 → Apache/Nginx → Docker dashboard:8000
```

## Option A : React + Tailwind + SSE (Recommandé)
- **Frontend** : React + Vite + Tailwind CSS
- **Backend** : FastAPI avec SSE (déjà existant)
- **Auth** : Formulaire login HTML → session cookie
- **Avantages** : UI moderne, animations, responsive
- **Dépendances** : Node.js pour build, mais servi par FastAPI

### Structure
```
dashboard/
├── frontend/          # React + Tailwind
│   ├── src/
│   │   ├── components/AttackFeed.jsx
│   │   ├── App.jsx
│   │   └── main.jsx
│   └── package.json
├── backend/           # FastAPI (déjà existant)
└── docker-compose.yml   # Service dashboard
```

## Option B : HTMX + Alpine.js (Léger)
- **Frontend** : HTMX + Alpine.js (CDN)
- **Backend** : FastAPI (templates Jinja2 + SSE)
- **Auth** : Formulaire HTML → session cookie
- **Avantages** : Aucun build, simple, efficace
- **Approche** : Server-side rendering + live updates

## Authentification Minimale
```html
<!-- Page login intégrée -->
<form action="/login" method="POST">
  <input name="password" type="password" placeholder="Mot de passe">
  <button>Connexion</button>
</form>

<!-- Session cookie HttpOnly -->
<!-- Plus besoin de header Authorization -->
```

## Étapes d'implémentation

### 1. Auth Cookie-Based (priorité)
- [ ] Ajouter endpoint `/login` avec formulaire HTML
- [ ] Créer session cookie `HttpOnly` + `SameSite=Strict`
- [ ] Middleware FastAPI pour vérifier session
- [ ] Route `/logout` pour invalider session

### 2. UI Moderne
- Option A : Créer `dashboard/frontend/` avec React
- Option B : Modifier templates existants avec HTMX

### 3. Live Updates
- [ ] SSE maintenu pour `/dashboard/stream`
- [ ] Reconnect automatique si déconnecté
- [ ] Indicateur "Live" pulsé en vert

### 4. Affichage Attaques
- [ ] Carte mondiale (CDN: leaflet.js)
- [ ] Timeline verticale des événements
- [ ] Filtres par type d'attaque
- [ ] Counter en temps réel

## Fichiers à créer/modifier
- `src/api/endpoints/auth.py` : routes login/logout
- `src/api/middleware/session.py` : vérification cookie
- `dashboard/frontend/` : UI React OU templates Jinja2
- `~/.hermes/honeypot-config/dashboard-vhost.conf` : reverse proxy
- `.env.example` : `DASHBOARD_PASSWORD=xxx`

## Validation
```bash
# Après déploiement
open http://dashboard.hiddenlabs.cc
# 1. Page login s'affiche
# 2. Entrer password → dashboard
# 3. Events SSE apparaissent en temps réel
```

## Choix Frontend
- React : Si vous voulez animations avancées, dev experience
- HTMX : Si vous voulez simplicité, aucune dépendance build