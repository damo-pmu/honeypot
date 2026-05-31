"""Safety isolator for decoy responses - prevents data leakage"""
import re
from typing import Optional
from pydantic import BaseModel


class SafetyCheck(BaseModel):
    """Safety validation result"""
    safe: bool
    reason: Optional[str] = None
    blocked_content: Optional[str] = None


class SafetyIsolator:
    """Ensures no real data leakage in decoy responses"""
    
    # Patterns that must NEVER appear in responses
    BLOCKED_PATTERNS = [
        r"BEGIN RSA PRIVATE KEY",
        r"Procyon mark: true",  # Real secret marker
        r"SECRET_KEY",
        r"api_key",
        r"password.*[Mm]ailgun",
        r"@hiddenlabs\.cc",  # Real domain
        r"[a-z]{32,}",  # Long random tokens
    ]
    
    # Allowed templates only
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
        "ai_challenge/cognitive_trap"
    }
    
    def validate_response(self, content: str, template: str) -> SafetyCheck:
        """Validate response content for safety"""
        
        # Check template is allowed
        if template not in self.ALLOWED_TEMPLATES:
            return SafetyCheck(
                safe=False,
                reason=f"Template {template} not in allowlist"
            )
        
        # Check for blocked patterns
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
        dangerous_patterns = [
            r"rm\s+-rf\s+/",
            r">\s*/etc/",
            r"/etc/shadow",
            r"mkfs",
            r"dd\s+if=",
            r"proxychains",
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, cmd, re.IGNORECASE):
                return None  # Block command
        
        return cmd  # Safe to process


# Safe credential patterns (obviously fake)
SAFE_CREDENTIALS = [
    "admin:Password123!",
    "root:toor",
    "user:changeme",
    "Administrator:Summer2024!",
    "backup:B@ckupKey2024"
]