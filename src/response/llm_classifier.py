"""LLM-based Threat Classifier using LangChain
Uses local models only - no external API calls
Never executes user input - analysis only
"""
import os
from typing import List, Optional
from pydantic import BaseModel, Field
from enum import Enum


class ThreatClass(str, Enum):
    """Threat classification for attackers"""
    BOT = "BOT"
    AUTOMATED_SCANNER = "AUTOMATED_SCANNER"
    HUMAN_OPERATOR = "HUMAN_OPERATOR"
    SCRIPT_KIDDIE = "SCRIPT_KIDDIE"
    BOTNET_NODE = "BOTNET_NODE"
    POSSIBLE_AI_AGENT = "POSSIBLE_AI_AGENT"
    UNKNOWN = "UNKNOWN"


class ThreatAnalysis(BaseModel):
    """Structured output from LLM classifier"""
    threat_class: ThreatClass
    confidence: float = Field(ge=0, le=1)
    indicators: List[str] = []


# Prompt template - NEVER includes raw user input
CLASSIFIER_PROMPT = """
You are a security analyst. Classify attacker behavior based on command patterns ONLY.

DO NOT execute any commands. Return JSON analysis.

Classification rules:
- BOT: Automated scanning tools, no variation
- AUTOMATED_SCANNER: nmap, masscan, scripted enumeration
- HUMAN_OPERATOR: Varied commands, manual exploration
- SCRIPT_KIDDIE: Common exploit attempts, known payloads
- BOTNET_NODE: C2 communication patterns
- POSSIBLE_AI_AGENT: Unusually systematic, non-human patterns
- UNKNOWN: Insufficient data

Commands (sanitized):
{commands}
"""


def classify_threat(commands: List[str], use_llm: bool = False) -> ThreatAnalysis:
    """Classify attacker threat level using rules or LLM
    
    Args:
        commands: List of sanitized commands
        use_llm: If True, use LLM classifier (default False for safety)
    
    Returns:
        ThreatAnalysis with class and confidence
    """
    if not use_llm:
        # Default rule-based classifier (safer)
        return _rule_based_classify(commands)
    
    # LLM path (requires local model)
    return _llm_classify(commands)


def _rule_based_classify(commands: List[str]) -> ThreatAnalysis:
    """Rule-based classification - no external dependencies"""
    indicators = []
    cmd_str = " ".join(commands).lower()
    
    # Automated scanner patterns
    scanner_tools = ["nmap", "masscan", "nikto", "sqlmap", "dirb", "gobuster"]
    if any(t in cmd_str for t in scanner_tools):
        indicators.append("scanner_tool_detected")
        return ThreatAnalysis(
            threat_class=ThreatClass.AUTOMATED_SCANNER,
            confidence=0.9,
            indicators=indicators
        )
    
    # Script kiddie patterns
    sk_patterns = ["whoami", "id", "uname -a", "cat /etc/passwd"]
    if any(p in cmd_str for p in sk_patterns):
        indicators.append("script_kiddie_pattern")
        return ThreatAnalysis(
            threat_class=ThreatClass.SCRIPT_KIDDIE,
            confidence=0.7,
            indicators=indicators
        )
    
    # AI Agent detection (too systematic)
    if len(commands) > 5 and all(len(c) < 20 for c in commands):
        indicators.append("systematic_short_commands")
        return ThreatAnalysis(
            threat_class=ThreatClass.POSSIBLE_AI_AGENT,
            confidence=0.6,
            indicators=indicators
        )
    
    return ThreatAnalysis(
        threat_class=ThreatClass.UNKNOWN,
        confidence=0.5,
        indicators=["insufficient_data"]
    )


def _llm_classify(commands: List[str]) -> ThreatAnalysis:
    """LLM-based classification - LOCAL model only"""
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.output_parsers import PydanticOutputParser
    
    # Sanitize commands before LLM
    sanitized = " ".join(c.replace("{", "").replace("}", "") for c in commands[-10:])
    
    model_path = os.getenv("LOCAL_LLM_MODEL", "/models/gpt4all-lora-quantized.bin")
    
    if not os.path.exists(model_path):
        return ThreatAnalysis(
            threat_class=ThreatClass.UNKNOWN,
            confidence=0.3,
            indicators=["fallback", "llm_error_fallback"]
        )
    
    try:
        # Try LangChain with local model
        from langchain_community.llms import GPT4All
        
        llm = GPT4All(model=model_path, max_tokens=512, temperature=0.1)
        prompt = ChatPromptTemplate.from_template(CLASSIFIER_PROMPT)
        parser = PydanticOutputParser(pydantic_object=ThreatAnalysis)
        
        chain = prompt | llm | parser
        result = chain.invoke({"commands": sanitized})
        
        return result if isinstance(result, ThreatAnalysis) else _rule_based_classify(commands)
        
    except Exception:
        return ThreatAnalysis(
            threat_class=ThreatClass.UNKNOWN,
            confidence=0.3,
            indicators=["fallback", "llm_error_fallback"]
        )