# Dashboard Feature - Real-time Honeypot Monitoring

## Vue d'ensemble
Dashboard moderne avec authentification minimale et affichage temps réel des attaques.

## Architecture
```
User → honeypot.hiddenlabs.cc:80 → Apache Proxy → Docker:8000
                                    ↓
                            FastAPI + SSE + Sessions
```

## Authentification
- **Type** : Cookie-based session (HttpOnly + SameSite=Strict)
- **Login** : Formulaire HTML → `/login`
- **Logout** : `/logout`
- **Config** : `DASHBOARD_PASSWORD` dans `.env`

### Variables d'environnement
```env
DASHBOARD_PASSWORD=your-secure-password
```

## Fonctionnalités

### 1. Auth Minimale
- ✅ Pas d'en-tête Authorization
- ✅ Session cookie persistante (24h)
- ✅ Page login intégrée avec design moderne

### 2. Monitoring Temps Réel
- ✅ Server-Sent Events (SSE) pour live updates
- ✅ Reconnection automatique en cas d'erreur
- ✅ Indicateur "Live" animé

### 3. Statistiques
- Total des events
- Répartition par type d'attaque
- Compteur IPs uniques

### 4. Carte Interactive
- Leaflet.js (CDN) - World map
- Marqueurs positions attaques (nécessite GeoIP)

### 5. Filtres
- Filter par type : ssh_login, telnet, command
- UI dynamique avec HTMX

## Endpoints API

| Route | Méthode | Auth | Description |
|-------|---------|------|-------------|
| `/` | GET | ❌ | Page login/dashboard |
| `/login` | POST | ❌ | Authentification |
| `/logout` | GET | ❌ | Déconnexion |
| `/stream` | GET | ✅ | SSE endpoint |
| `/stats` | GET | ✅ | Statistiques JSON |
| `/events/recent` | GET | ✅ | Derniers événements |
| `/emit` | POST | ❌ | Émission événement (worker) |
| `/debug/status` | GET | ❌ | Diagnostics système |

## Debug Autonome

### Logs d'audit
Format JSON structuré - tous les appels sont tracés :
```json
{
  "timestamp": "2026-05-31T23:45:00Z",
  "level": "INFO",
  "logger": "honeypot.auth",
  "message": "Auth login success from 192.168.1.100",
  "data": {"action": "login", "success": true, "ip": "192.168.1.100"}
}
```

### Endpoint de diagnostic
`GET /dashboard/debug/status` → État interne en temps réel :
- `events_pending` : Nombre d'événements en mémoire
- `event_types` : Répartition par type
- `sessions_active` : Sessions ouvertes
- `memory_usage` : Statut mémoire

### Middleware Audit
Toutes les requêtes API sont loggées avec :
- Méthode et chemin
- IP client
- User-Agent
- Durée de réponse
- Erreurs avec traceback

## Déploiement

### Configuration Apache
Fichier : `~/.hermes/honeypot-config/honeypot.hiddenlabs.cc.conf`

```apache
ProxyPass /dashboard/stream http://localhost:8000/dashboard/stream connectiontimeout=5 retry=0
ProxyPass /dashboard/ http://localhost:8000/dashboard/
```

### Docker
Le service `api` dans `docker-compose.yml` expose déjà le port 8000.

## Tests
```bash
# Test connexion
curl -X POST http://localhost:8000/dashboard/login \
  -d "password=test123" \
  -c cookies.txt

# Accéder aux stats
curl -b cookies.txt http://localhost:8000/dashboard/stats
```

## Dépendances Frontend (CDN)
- Pico.css: Framework CSS léger
- HTMX: Interactions sans build
- Leaflet.js: Carte interactive

## Sécurité
- ✅ Cookies HttpOnly
- ✅ SameSite=Strict
- ✅ Headers Apache (X-Frame-Options, X-XSS-Protection)
- ✅ HTTPS recommandé (Cloudflare)