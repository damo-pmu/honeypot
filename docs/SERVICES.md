# Services Métier - Honeypot SOC

> Code-first documentation - alignée avec src/services/*.py

---

## Attacker Profiler (`attacker_profiler.py`)

### Purpose
Classifier l'infrastructure d'origine de l'attaquant.

### Infrastructure types
```python
class InfrastructureType(str, Enum):
    TOR = "tor"
    VPN = "vpn"
    CLOUD = "cloud"
    HOSTING = "hosting"
    RESIDENTIAL = "residential"
    UNKNOWN = "unknown"
```

### Detection patterns
- **TOR** : IPs dans exit nodes list
- **VPN** : ASN patterns + residential flags
- **CLOUD** : AWS/GCP/Azure IP ranges
- **HOSTING** : ASN hosting providers

### Usage
```python
# Pattern match sur IP
infra = classify_infrastructure(ip_address)
# Returns InfrastructureType enum
```

---

## Behavior Analyzer (`behavior_analyzer.py`)

### Purpose
Détecter si l'attaquant est humain ou bot.

### Analyse patterns
- **Typing speed** : chars/sec (bots = constant)
- **Command intervals** : pauses entre actions
- **Correction patterns** : backspace/retyping
- **Timing randomness** : variabilité

### Décision
- Humain : variance élevée, pauses aléatoires
- Bot : timing constant, patterns répétitifs

---

## Campaign Engine (`campaign_engine.py`)

### Purpose
Détecter des campagnes d'attaque coordonnées.

### Détection
- IPs multiples avec timeline similaires
- Même sequence de commandes
- Attaques du même pays ASN

### Output
- `campaign_id` attribué aux sessions
- Corrélation temporelle +/- 2h

---

## Correlation Engine (`correlation_engine.py`)

### Purpose
Corréler événements entre sessions.

### Patterns
- IOC partagé entre sessions
- IPs liées (même /24)
- Timestamps proches

---

## IOC Extractor (`ioc_extractor.py`)

### Purpose
Extraction avancée d'indicateurs.

### Patterns supportés
- Hashes : MD5, SHA1, SHA256
- IPs : IPv4 avec validation
- URLs : HTTP/HTTPS
- Domains : TLD check

### Techniques
- Regex compilation + caching
- Fuzzy matching pour variantes

---

## MITRE Mapper (`mitre_mapper.py`)

### Purpose
Mapper les techniques d'attaque ATT&CK.

### Mapping
- `nmap` → Reconnaissance (T1046)
- `wget/curl` → Exfiltration (T1071)
- `whoami` → Discovery (T1033)

### Output
- Technique ID
- Tactic (initial_access, execution, etc)

---

## Replay Service (`replay_service.py`)

### Purpose
Reconstituer chronologiquement une session.

### Events
```python
@dataclass
class ReplayEvent:
    timestamp: datetime
    action: str  # connect, login, command, download
    payload: str
    severity: int
```

### Endpoints
- `GET /dashboard/api/replay/{session_id}`

---

## Risk Engine (`risk_engine.py`)

### Purpose
Calculer score de risque global.

### Facteurs
- Threat score initial
- IOC hits upsert
- Behavior classification

### Formule
```
risk = base_score + (ioc_weight * hits) + behavior_modifier
```

---

## Statistics Service (`statistics_service.py`)

### Purpose
Agrégations statistiques.

### Métrics
- Attack rate per minute
- Top attackers
- Protocol distribution
- Severity histogram

---

## Threat Intel Service (`threat_intel_service.py`)

### Purpose
Enrichir IOCs via sources externes.

### Threat Intel Sources
- AbuseIPDB : réputation IP
- Greynoise : noise vs signal  
- VirusTotal : hash verification
- OTX : pulse info

### Cache Strategy
Redis avec TTL 24h pour éviter rate limiting des APIs tierces.

## IOC Extraction Flow

```mermaid
flowchart TD
    A[Command text] --> B[Regex scan]
    B --> C{Hash patterns?}
    C -->|yes| D[Store hash IOCs]
    B --> E{IP patterns?}
    E -->|yes| F[Store IP IOCs]
    B --> G{URL patterns?}
    G -->|yes| H[Store URL IOCs]
    D --> I[/ioc/store]
    F --> I
    H --> I
```

---

## Timeline Builder (`timeline_builder.py`)

### Purpose
Construire timelines d'attaque.

### Events
- Session connect
- Login attempt
- Command execution
- Download
- Session close

### Format
Timeline JSON + graph dependencies