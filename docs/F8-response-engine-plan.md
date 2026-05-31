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

### 2. Behavior Detector (`src/detection/behavior.py`)
- AI fingerprinting patterns:
  - Unusual command sequences
  - Too-perfect typos
  - Systematic enumeration
  - Timing patterns (too regular)

### 3. Response Templates (inline in code - NO separate files)
Templates are defined in `src/response/router.py` `RESPONSE_TEMPLATES` dict:
- cisco_router/show_version, cisco_router/running_config
- windows_server/credentials (fake creds: Administrator:Summer2024!)
- jenkins_ci/config (fake Jenkins config)
- ai_challenge/cognitive_trap (for AI detection)

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
- `src/response/router.py` ✅ - Decision engine
- `src/response/safety.py` ✅ - Safety checks  
- `src/api/endpoints/response.py` ✅ - API routes (add `/responses/log` endpoint)
- `migrations/003_responses_tables.sql` - DB schema for responses table
- `tests/test_response_engine.py` ✅ - Tests