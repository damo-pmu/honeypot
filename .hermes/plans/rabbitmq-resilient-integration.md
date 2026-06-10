# Plan d'Intégration RabbitMQ - Gestion Resiliente des Events

## 🎯 Objectif
Remplacer le polling JSON par un système de messaging RabbitMQ avec résilience complète (ack, retry, DLQ, persistance) pour ne perdre aucun événement Cowrie.

## 📋 Current State Analysis

### Architecture Actuelle
```
Cowrie → /cowrie/var/log/cowrie/cowrie.json (file)
           ↓ (polling par worker)
       Worker (cowrie_ingest.py) - scan les nouvelles lignes
           ↓ (HTTP POST)
       API - /events, /internal/sessions
```

### Points de Frac
1. **Perte de données** si worker plante entre deux polls
2. **Monopole de requêtage** - le worker est le seul lecteur
3. **Pas de retry mechanism** en cas d'échec API
4. **Pas de backpressure** - API saturate = perte d'events

## 🛠️ Architecture Cible

```
Cowrie → RabbitProducer (plugin/custom)
           ↓
       Exchange cowrie.events (topic)
           ├── Queue cowrie.sessions (session.connect, session.closed)
           ├── Queue cowrie.auth (login.attempt, login.success)
           ├── Queue cowrie.commands (command.input)
           └── Queue cowrie.downloads (file.download)
           ↓
       Worker (consumers avec ack/reject)
           ↓
       API /events (persistant, avec retry)
           ↓
       Dead Letter Queue (échecs répétés)
```

## 🔧 Step-by-Step Implementation

### Phase 1: Configuration RabbitMQ (Day 1)
1. **Créer exchange déclaratif** dans `docker/rabbitmq/definitions.json`
   - Exchange: `cowrie.events` (type: topic, durable: true)
   - Queues: `cowrie.sessions`, `cowrie.auth`, `cowrie.commands`, `cowrie.downloads`
   - DLQ: `cowrie.dlq` avec TTL/expire

2. **Activer le plugin Cowrie RabbitMQ**
   - Modifier `cowrie.cfg` pour ajouter output RabbitMQ
   - Ou créer un wrapper producer dans le worker

### Phase 2: Producer Integration (Day 1-2)
3. **Créer `src/messaging/rabbitmq_producer.py`**
   ```python
   # Connection singleton avec reconnection auto
   # Publish functions pour chaque type d'event
   # Async non-blocking pour ne pas ralentir Cowrie
   ```

4. **Worker modifié (`cowrie_ingest.py`)**
   - Lire les events depuis file JSON
   - Publier dans RabbitMQ AVEC ack système
   - Marquer line comme "published" après ack

5. **Persistent state file** (`cowrie_published.log`)
   - Offset des lignes traitées
   - Reprise après plantage

### Phase 3: Consumer Resilient (Day 2-3)
6. **Créer `src/messaging/rabbitmq_consumer.py`**
   ```python
   # aio-pika connection
   # QoS (prefetch=10) pour contrôle débit
   # Manual ack après succès API
   # Reject + requeue pour erreurs temporaires
   # Dead letter après N tentatives
   ```

7. **Handlers par type d'event**
   - `handle_session()`
   - `handle_auth()`
   - `handle_command()`
   - `handle_download()`

### Phase 4: Monitoring & Alerting (Day 3)
8. **Health check RabbitMQ**
   - Consumer lag metrics
   - Queue depth alert thresholds

9. **Retry logic robuste**
   - Exponential backoff
   - Circuit breaker si API down > 5min

## 📂 Fichiers à Créer/Modifier

### À Créer
- `src/messaging/__init__.py`
- `src/messaging/rabbitmq_client.py` (connection pooled)
- `src/messaging/rabbitmq_producer.py`
- `src/messaging/rabbitmq_consumer.py`
- `src/messaging/event_handlers.py`
- `docker/rabbitmq/definitions.json`
- `tests/messaging/test_rabbitmq.py`

### À Modifier
- `src/worker/cowrie_ingest.py` → ajouter publish RabbitMQ
- `src/api/endpoints/dashboard_v3.py` → ajouter retry endpoint /events
- `docker-compose.yml` → ajouter definition volume
- `requirements.txt` → pin aio-pika version exacte

## 🧪 Tests & Validation

### Tests Unitaires
```bash
# Test producer
pytest tests/messaging/test_producer.py -v

# Test consumer
pytest tests/messaging/test_consumer.py -v
```

### Tests d'Intégration
1. Simuler 1000 events SSH
2. Arrêter worker pendant 30s
3. Redémarrer → vérifier tous les events sont consommés
4. Arrêter API → vérifier retry + DLQ

### Validation Production
```bash
# Queue depth stable
curl -s localhost:8000/messaging/stats

# DLQ empty
rabbitmqctl list_queue_messages cowrie.dlq

# Consommation temps réel
curl -s localhost:8000/api/live-feed
```

## ⚠️ Risques & Mitigations

| Risque | Mitigation |
|--------|------------|
| Perte events pendant migration | Dual write: JSON + RabbitMQ pendant 24h |
| Memory leak RabbitMQ connexions | Singleton + context manager |
| Queue explosion si API down | TTL 6h + DLQ max 10k messages |
| Ordre des messages | Utiliser x-single-active-consumer ou sessions partitionnées |

## 📚 Librairies Maintenues & Standards

- **aio-pika >= 9.2.0** (déjà dans requirements) - ASGI native
- **Pattern Library**: `rabbitmq/amqp091-go` patterns (acknowledgement, DLQ)
- **Backoff**: `asyncio.sleep` avec exponential backoff standard
- **Health**: `aiohttp` health checks intégrés

## 🚀 Deployment Strategy

1. **Canary**: Worker avec RabbitMQ en parallèle du polling (24h)
2. **Cutover**: Uniquement RabbitMQ après validation
3. **Rollback**: Retour polling si incident

## 📝 Notes d'Implémentation

- Utiliser `os.getenv("RABBITMQ_URL")` avec défaut `amqp://guest:guest@rabbitmq:5672/`
- Consumer group pour scalabilité horizontale
- Metrics Prometheus via `/metrics` endpoint