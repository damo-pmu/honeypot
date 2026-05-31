"""Response API endpoints - exposes decoy response engine"""
from fastapi import APIRouter, HTTPException
from typing import Optional
from pydantic import BaseModel
from datetime import datetime

router = APIRouter(prefix="/response", tags=["response"])


class ResponseRequest(BaseModel):
    session_id: str
    attacker_ip: str
    threat_class: str
    interaction_count: int = 0


class ResponseOutput(BaseModel):
    session_id: str
    decision: str
    template: Optional[str]
    content: Optional[str]
    timestamp: datetime


@router.post("/generate", response_model=ResponseOutput)
def generate_response(request: ResponseRequest):
    """Generate decoy response based on attacker profile"""
    from src.response.router import decide_response, get_response_content
    from src.response.safety import SafetyIsolator
    
    # Get decision
    decision = decide_response(
        session_id=request.session_id,
        attacker_ip=request.attacker_ip,
        threat_class=request.threat_class,
        confidence=0.5,  # Would come from classifier
        interaction_count=request.interaction_count
    )
    
    # Get content
    content = None
    if decision.template_name:
        content = get_response_content(decision.template_name)
        # Validate
        safety = SafetyIsolator()
        check = safety.validate_response(content or "", decision.template_name or "")
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
    return {"templates": list(RESPONSE_TEMPLATES.keys())}


@router.get("/decoy/{template}")
def get_decoy(template: str, interaction_level: int = 0):
    """Get full decoy environment for template"""
    from src.response.fake_env import get_decoy_by_template
    
    result = get_decoy_by_template(template, interaction_level)
    if not result:
        raise HTTPException(status_code=404, detail=f"Template {template} not found")
    return result.model_dump()