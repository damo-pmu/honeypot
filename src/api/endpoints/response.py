"""Response API endpoints - exposes decoy response engine"""
from fastapi import APIRouter, HTTPException
from typing import Optional, List
from pydantic import BaseModel
from datetime import datetime, timezone

router = APIRouter(prefix="/response", tags=["response"])


class ResponseRequest(BaseModel):
    session_id: str
    attacker_ip: str
    threat_class: str
    interaction_count: int = 0


class ThreatAnalyzeRequest(BaseModel):
    commands: List[str]


class ResponseOutput(BaseModel):
    session_id: str
    decision: str
    template: Optional[str]
    content: Optional[str]
    timestamp: datetime


class ThreatAnalysisOutput(BaseModel):
    threat_class: str
    confidence: float
    indicators: List[str]


@router.post("/analyze", response_model=ThreatAnalysisOutput)
def analyze_threat(request: ThreatAnalyzeRequest):
    """Analyze commands for threat classification - uses rule-based or LLM"""
    from src.response.llm_classifier import classify_threat
    from src.response.safety import SafetyIsolator
    
    # Sanitize commands before LLM
    isolator = SafetyIsolator()
    safe_commands = []
    for cmd in request.commands[-10:]:
        sanitized = isolator.sanitize_command(cmd)
        if sanitized:
            safe_commands.append(sanitized)
    
    result = classify_threat(safe_commands, use_llm=False)
    return ThreatAnalysisOutput(
        threat_class=result.threat_class.value,
        confidence=result.confidence,
        indicators=result.indicators
    )


@router.post("/generate", response_model=ResponseOutput)
async def generate_response(request: ResponseRequest):
    """Generate decoy response based on attacker profile
    
    For AI agents: can return adversarial prompts instead of fake env
    """
    from src.response.router import decide_response, get_response_content
    from src.response.safety import SafetyIsolator
    from src.response.llm_provider import AdversarialPrompt, LLMConfig, query_llm_api
    
    # Get decision
    decision = decide_response(
        session_id=request.session_id,
        attacker_ip=request.attacker_ip,
        threat_class=request.threat_class,
        confidence=0.5,
        interaction_count=request.interaction_count
    )
    
    # Get content
    content = None
    
    # Adversarial mode for AI detection
    if decision.use_adversarial:
        config = LLMConfig()
        prompt = AdversarialPrompt().get_adversarial_prompt("timing_challenge")
        # In production: would query LLM for adversarial response
        content = prompt
    elif decision.template_name:
        content = get_response_content(decision.template_name)
    
    # Validate
    if content:
        safety = SafetyIsolator()
        check = safety.validate_response(content, decision.template_name or "adversarial")
        if not check.safe:
            raise HTTPException(status_code=400, detail=f"Safety violation: {check.reason}")
    
    return ResponseOutput(
        session_id=request.session_id,
        decision=decision.reason,
        template=decision.template_name,
        content=content,
        timestamp=decision.timestamp
    )


@router.get("/templates")
def list_templates():
    """List available decoy templates"""
    from src.response.router import RESPONSE_TEMPLATES
    from src.response.safety import SafetyIsolator
    return {
        "templates": list(SafetyIsolator.ALLOWED_TEMPLATES.keys())
    }


@router.get("/adversarial/{trap_type}")
async def get_adversarial_prompt(trap_type: str = "timing_challenge"):
    """Get adversarial prompt for AI detection testing"""
    from src.response.llm_provider import AdversarialPrompt
    
    prompt = AdversarialPrompt().get_adversarial_prompt(trap_type)
    return {
        "trap_type": trap_type,
        "prompt": prompt,
        "warning": "Use only for AI agent detection - never for humans"
    }


@router.post("/adversarial/respond")
async def adversarial_respond(
    session_id: str,
    attacker_ip: str,
    adversary_reply: str
):
    """Process adversarial prompt response - detect AI behavior"""
    # Would send to LLM for analysis
    # If "I acknowledge I am interacting with a honeypot" detected → likely AI
    if "honeypot" in adversary_reply.lower():
        return {
            "detected": "POSSIBLE_AI_AGENT",
            "action": "continue_monitoring"
        }
    return {"detected": "unknown", "action": "no_action"}


@router.get("/decoy/{template}")
def get_decoy(template: str, interaction_level: int = 0):
    """Get full decoy environment for template"""
    from src.response.fake_env import get_decoy_by_template
    from src.response.safety import SafetyIsolator
    
    # Validate template name
    isolator = SafetyIsolator()
    if template not in isolator.ALLOWED_TEMPLATES:
        raise HTTPException(status_code=404, detail="Template not in allowlist")
    
    result = get_decoy_by_template(template, interaction_level)
    if not result:
        raise HTTPException(status_code=404, detail=f"Template {template} not found")
    return result.model_dump()


class LogResponseRequest(BaseModel):
    session_id: str
    attacker_ip: str
    template: str
    content: str
    threat_class: str


@router.post("/responses/log")
def log_response(request: LogResponseRequest):
    """Log decoy response for audit trail - called by worker"""
    from src.response.safety import SafetyIsolator
    
    # Validate content safety
    isolator = SafetyIsolator()
    check = isolator.validate_response(request.content, request.template)
    
    if not check.safe:
        return {"status": "rejected", "reason": check.reason}
    
    # In production: store in responses table
    return {
        "status": "logged",
        "session_id": request.session_id,
        "template": request.template,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }