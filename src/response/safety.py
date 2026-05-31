"""Safety isolator for decoy responses - prevents data leakage"""
import re
from typing import Optional, List
from pydantic import BaseModel

# Export patterns for other modules
DANGEROUS_PATTERNS = [
    r"rm\s+-rf\s+/",           # Destruction
    r"mkfs",                   # Format disk
    r">\s*/dev/sd",           # Device write
    r"/etc/passwd",           # System files
    r"/etc/shadow",           # System files
    r"curl.*http",            # Outbound calls
    r"wget\s+",               # Downloads
    r"nc\s+-",                # Reverse shells
    r"proxychains",           # Proxy tunneling
    r"ssh\s+.*@",            # Outbound SSH
    r"bash\s+-i",            # Interactive shell
    r"/dev/tcp",             # Bash network
    r"python.*-c",           # Python inline
    r"perl.*-e",             # Perl inline
    r"eval\(",               # Code execution
    r"base64.*decode",        # Encoded payloads
    r"sh\s+-c",              # Shell execution
]


class SafetyCheck(BaseModel):
    """Safety validation result"""
    safe: bool
    reason: Optional[str] = None
    blocked_content: Optional[str] = None


class SafetyIsolator:
    """Ensures no real data leakage in decoy responses - NEVER trusts user input"""
    
    # Patterns that must NEVER appear in responses (prevent real data leakage)
    BLOCKED_PATTERNS = [
        r"BEGIN RSA PRIVATE KEY",
        r"-----BEGIN CERTIFICATE",
        r"Procyon mark: true",  # Real secret marker
        r"SECRET_KEY",
        r"api_key.*[A-Za-z0-9]{20,}",
        r"@hiddenlabs\.cc",  # Real domain
        r"[a-z]{32,}",  # Long random tokens
        r"password\s*=\s*['\"][A-Za-z0-9]{20,}['\"]",  # Real passwords
    ]
    
    # Allowed templates only - whitelist principle
    ALLOWED_TEMPLATES = {
        "cisco_router/show_version",
        "cisco_router/running_config", 
        "cisco_router/show_arp",
        "cisco_router/show_cdp",
        "windows_server/credentials",
        "windows_server/web_config",
        "windows_server/notes",
        "jenkins_ci/config",
        "jenkins_ci/users",
        "jenkins_ci/secrets",
        "ai_challenge/cognitive_trap",
        "adversarial/timing_challenge",
        "adversarial/context_trap"
    }
    
    def validate_response(self, content: str, template: str) -> SafetyCheck:
        """Validate response content for safety - blocking is default"""
        
        # Check template is allowed (whitelist)
        if template not in self.ALLOWED_TEMPLATES:
            return SafetyCheck(
                safe=False,
                reason=f"Template {template} not in allowlist"
            )
        
        # Check for blocked patterns in content
        for pattern in self.BLOCKED_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return SafetyCheck(
                    safe=False,
                    reason=f"Blocked pattern detected: {pattern}",
                    blocked_content=content[:100]
                )
        
        return SafetyCheck(safe=True)
    
    def sanitize_command(self, cmd: str) -> Optional[str]:
        """Sanitize command input - returns None if dangerous"""
        
        # Check against dangerous patterns
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                return None  # Block command
        
        # Return sanitized version (command itself is never executed, only analyzed)
        return cmd
    
    def prepare_for_llm(self, commands: List[str]) -> str:
        """Prepare command list for LLM analysis - removes sensitive data"""
        sanitized = []
        for cmd in commands[-10:]:  # Last 10 commands only
            # Remove any apparent secrets from commands going to LLM
            clean = re.sub(r"['\"][A-Za-z0-9/+]{20,}['\"]", "[REDACTED]", cmd)
            clean = re.sub(r"https?://[^\\s]+", "[URL]", clean)
            sanitized.append(clean)
        return "\n".join(sanitized)


# Safe credential patterns (obviously fake - see in training data)
SAFE_CREDENTIALS = [
    "admin:Password123!",
    "root:toor",
    "user:changeme",
    "Administrator:Summer2024!",
    "backup:B@ckupKey2024"
]