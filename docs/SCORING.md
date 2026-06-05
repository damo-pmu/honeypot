# Scoring Engine & Threat Classification

> Code-first documentation - alignée avec src/scoring/engine.py + src/response/llm_classifier.py

## Scoring Rules Engine

### Attack types & scores

| Attack Type | Score | Description |
|-----------|-------|-------------|
| BRUTE_FORCE | 20 | Auth attempts |
| SQL_INJECTION | 30 | SQL injection attempts |
| MALWARE_DOWNLOAD | 50 | wget/curl downloads |
| PORT_SCAN | 15 | nmap/masscan |
| RECONNAISSANCE | 10 | whoami/id/uname |
| AI_AGENT_PATTERN | 25 | Systematic short commands |

### Classification thresholds

```python
# src/scoring/engine.py:37-46
def classify_threat(score: int) -> str:
    if score >= 50:      return "BOTNET_NODE"
    elif score >= 30:    return "AUTOMATED_SCANNER"
    elif score >= 15:    return "SCRIPT_KIDDIE"
    else:                return "UNKNOWN"
```

## Flow classification

```mermaid
flowchart TD
    A[Command received] --> B[Rule-based scan]
    B --> C{Scanner tool?}
    C -->|yes| D[THREAT=AUTOMATED_SCANNER]
    C -->|no| E{Whoami/id?}
    E -->|yes| F[THREAT=SCRIPT_KIDDIE]
    E -->|no| G{Systematic?}
    G -->|yes| H[THREAT=POSSIBLE_AI_AGENT]
    G -->|no| I[THREAT=UNKNOWN]
    D --> J[/response/generate]
    F --> J
    H --> J
    I --> J
```

## LLM Classifier

### Safety measures
- Templates statiques uniquement
- LLM local-only (`$LOCAL_LLM_MODEL`)
- Fallback rules si LLM échoue
- Sanitisation `{}` dans prompt

### Rule-based (default)

```python
# src/response/llm_classifier.py:67-104
scanner_tools = ["nmap", "masscan", "nikto", "sqlmap", "dirb", "gobuster"]
sk_patterns = ["whoami", "id", "uname -a", "cat /etc/passwd"]

if any(t in cmd for t in scanner_tools):
    return AUTOMATED_SCANNER, confidence=0.9
elif any(p in cmd for p in sk_patterns):
    return SCRIPT_KIDDIE, confidence=0.7
elif len(commands) > 5 and all(len(c) < 20 for c in commands):
    return POSSIBLE_AI_AGENT, confidence=0.6
```

## Risk Integration

Le scoring est utilisé pour :
1. Décision response template
2. Badge danger dans dashboard
3. Filtrage alertes sévères

### Endpoints concernés
- `POST /attacks/log` (severity depuis scoring)
- `POST /response/analyze` (threat_class depuis classifier)
- `GET /dashboard/api/stats` (badge danger)