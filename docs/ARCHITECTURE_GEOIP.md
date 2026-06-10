# 🏗️ Architecture GeoIP + Dashboard

## Flux de Données Complet

```
                    ┌──────────────────┐
                    │   TOR NETWORK    │
                    │  (seed attacks)  │
                    └────────┬─────────┘
                             │ ssh/telnet (real IPs)
                             ▼
┌─────────────────────────────────────────────────────────┐
│  ┌──────────────┐   ┌──────────────┐                    │
│  │ Cowrie (SSH) │   │ Cowrie (Telnet)│                  │
│  └──────┬───────┘   └──────┬───────┘                    │
│         │                  │                            │
│         ▼                  ▼                            │
│  /cowrie/var/log/cowrie/cowrie.json                      │
└────────┬─────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐     ┌──────────────────┐
│ RabbitMQ Producer│────►│ RabbitMQ Consumer│
│ (cowrie_producer)│     │ (geoip enrich)   │
└──────────────────┘     └────────┬─────────┘
                                   │
                                   ▼
        ┌────────────────────────────────────────┐
        │ PostgreSQL                             │
        │                                        │
        │ attackers: {ip, geoip, country, ...}   │
        │ sessions: {id, attacker_ip, ...}     │
        │ attacks: {attacker_ip, geoip...}       │
        └────────────────────────────────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         │                         │                         │
         ▼                         ▼                         ▼
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│ Dashboard Map    │   │ Dashboard Home   │   │ Analytics API    │
│ (Leaflet)        │   │ (Stats)          │   │ (/analytics/*)    │
│ - Markers        │   │ - Live feed      │   │ - Profiles       │
│ - Click linking  │   │ - Stats          │   │ - Commands       │
└──────────────────┘   └──────────────────┘   └──────────────────┘
```

## Services Docker

| Service | Rôle | Ports |
|---------|------|-------|
| `api` | FastAPI + Dashboard | 127.0.0.1:8000 |
| `postgres` | DB principale | 5432 |
| `redis` | Cache + DLQ tracking | 6379 |
| `rabbitmq` | Queue events | 5672, 15672 |
| `cowrie` | Honeypot SSH/Telnet | 22/23 |
| `tor` | Seed réseau (optionnel) | 9050 |

## Variables d'Environnement

```bash
# GeoIP
MMDB_PATH=/app/data/geolite2.mmdb

# Dashboard
DASHBOARD_PASS=your_secure_password

# Tor Seed (optionnel)
TOR_SEED_ENABLED=true
TOR_SEED_IPS=10  # Nombre d'IPs Tor à utiliser
PUBLIC_IP=YOUR_PUBLIC_IP  # Pour filtrer les vrais attaques
```

## Endpoints API GeoIP

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/attackers/{ip}/geolocation` | GET | Coords + sessions + attacks |
| `/attackers/{ip}/attacks` | GET | Liste attaques par IP |
| `/dashboard/map` | GET | Page carte interactive |
| `/dashboard/api/live-feed` | GET | Events enrichis geoip |

## Linking Visuel Dashboard

- **Click marker** → Highlight attacks feed + modal session
- **Click attack** → Fly to marker + modal session
- **Clustering** → Density par zone géographique