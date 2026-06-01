# Dashboard Architecture Plan

## Objectif
Intégrer le dashboard FastAPI dans docker-compose avec reverse proxy Apache sur `honeypot.hiddenlabs.cc`

## Architecture cible
```
User → honeypot.hiddenlabs.cc:80 → Apache reverse proxy → Docker:8000 (FastAPI)
```

## Étapes

### 1. Docker Integration
- [ ] Ajouter service `dashboard` dans `docker-compose.yml`
- [ ] Dockerfile pour l'API (FastAPI + Uvicorn)
- [ ] Port mapping : conteneur `8000` → host `8000` (interne)

### 2. Apache Reverse Proxy
- [ ] Virtual host `honeypot.hiddenlabs.cc` → proxy vers `localhost:8000`
- [ ] Modules requis : `proxy_http`, `proxy_wstunnel` (SSE), `headers`
- [ ] Headers de sécurité : `X-Content-Type-Options`, `X-Frame-Options`

### 3. Network
- [ ] Docker network `honeypot_internal`
- [ ] Ports exposés : 8000 (API interne), 2222 (Cowrie), 9090 (decoy)
- [ ] Dashboard uniquement via Apache (pas d'exposition directe publique)

### 4. Sécurité
- [ ] Token auth conservé (`DASHBOARD_TOKEN` via .env)
- [ ] HTTPS via Cloudflare (domaine déjà configuré)
- [ ] Rate limiting Apache (mod_ratelimit)

## Fichiers à créer/modifier
- `docker-compose.yml` : ajouter service dashboard
- `Dockerfile.api` : image FastAPI
- `~/.hermes/honeypot-config/honeypot.hiddenlabs.cc.conf` : vhost (hors repo)
- `.env` : `DASHBOARD_TOKEN`, `API_HOST=0.0.0.0`

## Dépendances
- Docker installé sur la machine
- Ports 80/443 ouverts (vérifier Security List OCI)
- Domaine DNS pointant vers 158.178.206.226

## Validation
```bash
curl -H "X-Dashboard-Token: $TOKEN" http://honeypot.hiddenlabs.cc/api/stats
```