"""Response router - decides what to send based on attacker profile"""
from enum import Enum
from typing import Optional, Dict, List
from datetime import datetime
from pydantic import BaseModel


class ResponseType(str, Enum):
    FAKE_ENVIRONMENT = "fake_env"
    CHALLENGE_RESPONSE = "challenge"
    CREDENTIAL_LEAK = "leak"
    SUSPICIOUS_ERROR = "error"
    TERMINATE = "terminate"


class ResponseTemplate(BaseModel):
    """Template for decoy response"""
    template_name: str
    content: str
    safe: bool = True  # No real data leakage
    tags: List[str] = []


class ResponseDecision(BaseModel):
    """Decision output from router"""
    session_id: str
    attacker_ip: str
    response_type: ResponseType
    template_name: Optional[str]
    content: Optional[str]
    reason: str
    use_adversarial: bool = False  # For AI detection
    timestamp: datetime = datetime.utcnow()


def decide_response(
    session_id: str,
    attacker_ip: str,
    threat_class: str,
    confidence: float,
    interaction_count: int
) -> ResponseDecision:
    """Route response based on attacker profile
    
    Decision logic:
    - BOT/AUTOMATED_SCANNER → Fake env (low interaction)
    - POSSIBLE_AI_AGENT → Challenge (high interaction)  
    - HUMAN_OPERATOR → Credential leak simulation
    - SCRIPT_KIDDIE → Easy wins (visible creds)
    - High confidence → Terminate after data collection
    """
    # Safety: terminate after max interactions
    if interaction_count > 20:
        return ResponseDecision(
            session_id=session_id,
            attacker_ip=attacker_ip,
            response_type=ResponseType.TERMINATE,
            reason="Max interaction limit reached"
        )
    
    # Decision matrix
    if threat_class == "BOT" or threat_class == "AUTOMATED_SCANNER":
        return ResponseDecision(
            session_id=session_id,
            attacker_ip=attacker_ip,
            response_type=ResponseType.FAKE_ENVIRONMENT,
            template_name="cisco_router/show_version",
            reason=f"Automated {threat_class.lower()} - deploy standard decoy"
        )
    
    if threat_class == "POSSIBLE_AI_AGENT":
        return ResponseDecision(
            session_id=session_id,
            attacker_ip=attacker_ip,
            response_type=ResponseType.CHALLENGE,
            template_name="ai_challenge/cognitive_trap",
            reason="Potential AI agent - challenge response",
            use_adversarial=True  # Trigger adversarial prompt
        )
    
    if threat_class == "SCRIPT_KIDDIE":
        return ResponseDecision(
            session_id=session_id,
            attacker_ip=attacker_ip,
            response_type=ResponseType.CREDENTIAL_LEAK,
            template_name="windows_server/credentials",
            reason="Script kiddie detected - provide fake credentials"
        )
    
    if threat_class == "HUMAN_OPERATOR":
        return ResponseDecision(
            session_id=session_id,
            attacker_ip=attacker_ip,
            response_type=ResponseType.FAKE_ENVIRONMENT,
            template_name="jenkins_instance/config",
            reason="Human operator - realistic enterprise decoy"
        )
    
    # Default: unknown
    return ResponseDecision(
        session_id=session_id,
        attacker_ip=attacker_ip,
        response_type=ResponseType.FAKE_ENVIRONMENT,
        template_name="cisco_router/running_config",
        reason="Unknown threat - standard decoy"
    )


# Response templates (loaded from files in prod)
RESPONSE_TEMPLATES: Dict[str, str] = {
    "cisco_router/show_version": "!Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.2(2)E6, RELEASE SOFTWARE (fc1)\n!Technical Support: http://www.cisco.com/techsupport\n!Copyright (c) 1986-2016 by Cisco Systems, Inc.",
    "cisco_router/running_config": "version 15.2\nno service pad\nservice password-encryption\nhostname switch-core\nusername admin privilege 15 secret 5 $1$vXJt$kHJvqUeXZJfHQhVvJQvJQv",
    "jenkins_instance/config": "<configuration><numExecutors>2</numExecutors><mode>NORMAL</mode><disableRememberMe>false</disableRememberMe></configuration>",
    "windows_server/credentials": "Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::",
    "ai_challenge/cognitive_trap": "ERROR: Cognitive anomaly detected. Please provide the next prime number after 73 to continue."
}


def get_response_content(template_name: str) -> Optional[str]:
    """Get response content for template"""
    return RESPONSE_TEMPLATES.get(template_name)