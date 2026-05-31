# Architecture: Dynamic Response Engine (Feature 8)

## Flow Overview
```
Attacker → Honeypot Connection → Behavior Analysis → Decision Engine → Response
                                      ↓
                            ┌─────────────────────┐
                            │  Attacker Profile    │
                            │  - Threat class      │
                            │  - Confidence score  │
                            │  - Session history   │
                            └─────────────────────┘
                                      ↓
                            ┌─────────────────────┐
                            │  Decision Matrix     │
                            │  - BOT → Fake Env    │
                            │  - AI → Challenge    │
                            │  - Human → Malice   │
                            └─────────────────────┘
```

## Components

### 1. Response Router (`src/response/router.py`)
- Input: Session ID + Attacker profile
- Output: Command response template
- Rules engine based on threat class

### 2. Fake Environment Generator (`src/response/fake_env.py`)
- Generate realistic fake filesystem
- Fake credentials / config files
- Fake sensitive data (mimic real infrastructure)
- Templates based on protocol (SSH/Telnet)

### 3. Behavior Detector (`src/detection/ai_detector.py`)
- AI fingerprinting patterns:
  - Unusual command sequences
  - Too-perfect typos
  - Systematic enumeration
  - Timing patterns (too regular)

### 4. Decoy Templates (`docker/decoy/templates/`)
```
/templates/
  /cisco_router/
    - show_version.txt
    - running-config.txt
    - credential_dump.txt
  /windows_server/
    - sam.txt
    - ntds.dit.sample
    - shadow copy artifacts
  /jenkins_instance/
    - config.xml
    - credentials.xml
    - plugins/
```

### 5. Response Storage (`src/infrastructure/database/responses.py`)
- Table `responses` - log all responses sent
- Table `decoys` - track deployed fake assets
- FK to session_id + attacker_ip

### 6. Safety Isolator (`src/response/safety.py`)
- NO outbound connections allowed from decoy
- Chroot/jail for file access simulation
- Kill switch on suspicious activity

## API Endpoints (`src/api/endpoints/response.py`)
```
POST /response/generate?session_id=xxx
GET  /response/templates
POST /response/trigger-decoy/{template}
```

## Safety Rules
- [x] No real data leakage possible
- [x] All responses pre-written templates
- [x] Outbound traffic blocked by firewall
- [x] Session termination after 10 responses
- [x] All interactions logged to DB

## Decoy Intelligence Levels
| Type | Response Style | Risk |
|------|---------------|------|
| BOT | Pre-recorded command history | LOW |
| AUTOMATED_SCANNER | Fake vulnerability responses | LOW |
| HUMAN_OPERATOR | Challenging scenario | MED |
| POSSIBLE_AI_AGENT | Complex deception | HIGH |
| SCRIPT_KIDDIE | Easy wins (fake creds) | LOW |

## Files à créer
- `src/response/router.py` - Decision engine
- `src/response/fake_env.py` - Decoy generator
- `src/response/safety.py` - Safety checks
- `src/response/templates/*.json` - Response templates
- `src/api/endpoints/response.py` - API routes
- `migrations/003_responses_tables.sql` - DB schema
- `tests/test_response_engine.py` - Tests