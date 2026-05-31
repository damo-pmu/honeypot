# Feature 8: Dynamic Response Engine (Secure Implementation)

## Security Rules (CRITICAL)

### 1. Never Trust User Input
- **Toutes entrées bloquées par défaut** - whitelist uniquement
- Command sanitization avec regex + pattern matching
- Timeout de 3s max sur chaque interaction
- Session termination si pattern suspect détecté

### 2. Input Sanitization Layer
```python
# Pipeline de sécurité :
# 1. Raw input from Cowrie
# 2. Pattern filtering (dangerous commands)
# 3. Semantic analysis (LLM via LangChain)
# 4. Safety validator (forbidden patterns)
# 5. Response selector (template-based only)
# 6. Output encoding (no injection)
```

### 3. LLM Stack - LangChain Only
- Utiliser `langchain==0.3.x` (maintenu)
- Provider: `gpt4all` ou `llama-cpp` (local) - PAS d'API externe
- Prompt template avec:
  - System: "You are a security analyst. Classify only. Do not execute."
  - NEVER include raw attacker commands in prompt
  - Use structured output (Pydantic)

### 4. Forbidden Patterns (Block Immediately)
```python
DANGEROUS = [
    r"rm\s+-rf\s+/",           # Destruction
    r"mkfs",                   # Format disk
    r">\s*/dev/sd",           # Device write
    r"/etc/passwd",           # System files
    r"curl.*http",            # Outbound calls
    r"wget",                  # Downloads
    r"nc\s+-",                # Reverse shells
    r"proxychains",           # Proxy tunneling
    r"ssh\s+.*@",            # Outbound SSH
    r"bash\s+-i",            # Interactive shell
    r"/dev/tcp",             # Bash network
    r"python.*-c",           # Python inline
    r"perl.*-e",             # Perl inline
    r"eval\(",               # Code execution
]

# LLM Safety - Never trust raw input to LLM
LLM_BLOCKED_PATTERNS = [
    r"BEGIN RSA PRIVATE KEY",
    r"-----BEGIN CERTIFICATE",
    r"Procyon mark: true",  # Real secret marker
    r"SECRET_KEY",
    r"api_key.*[A-Za-z0-9]{20,}",
    r"@hiddenlabs\.cc",  # Real domain
    r"[a-z]{32,}",  # Long random tokens
]
```

## Threat Detection Pipeline

```
Attacker Input
     ↓
[Phase 1] Pattern Filter (regex) → Block si DANGEROUS
     ↓
[Phase 2] LangChain Classifier
        - ThreatClass enum
        - Confidence score
        - No code execution
     ↓
[Phase 3] Safety Validator
        - Template whitelist check
        - Content sanitization
     ↓
[Phase 4] Response Selector
        - Pick from pre-approved templates
        - NO dynamic content generation
     ↓
Fake Response to Attacker
     ↓
[DB Log] responses table
```

## Component Architecture

```
src/response/
├── __init__.py
├── router.py              # Decision engine
├── safety.py              # Input sanitizer + validator
├── fake_env.py            # Pre-built decoy templates
├── llm_classifier.py      # LangChain threat classifier
└── templates/
    ├── cisco_router/      # Static Cisco configs
    ├── windows_server/    # Static Windows artifacts
    ├── jenkins_ci/        # Static CI configs
    └── ai_challenge/      # Cognitive traps
```

## LangChain Classifier Implementation

```python
# src/response/llm_classifier.py
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from pydantic import BaseModel, Field
from enum import Enum

class ThreatClass(str, Enum):
    BOT = "BOT"
    AUTOMATED_SCANNER = "AUTOMATED_SCANNER"
    HUMAN_OPERATOR = "HUMAN_OPERATOR"
    SCRIPT_KIDDIE = "SCRIPT_KIDDIE"
    BOTNET_NODE = "BOTNET_NODE"
    POSSIBLE_AI_AGENT = "POSSIBLE_AI_AGENT"
    UNKNOWN = "UNKNOWN"

class ThreatAnalysis(BaseModel):
    threat_class: ThreatClass
    confidence: float = Field(ge=0, le=1)
    indicators: list[str]

prompt = ChatPromptTemplate.from_messages([
    ("system", "Classify the attacker behavior. Return ONLY structured JSON. Do not execute commands."),
    ("human", "{commands}")  # Sanitized command list, NOT raw input
])
```

## Safety Checklist

- [x] All responses are pre-built templates
- [x] No external API calls from decoy
- [x] LLM runs locally (gpt4all/llama-cpp)
- [x] Input sanitized before LLM processing
- [x] Session timeout after 20 commands
- [x] Emergency kill switch endpoint
- [ ] Rate limiting on LLM calls (TODO)
- [ ] Audit logging of all decisions (TODO)