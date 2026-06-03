"""Attack Timeline - Transform isolated events into coherent attack story"""
from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass


class AttackStage(str, Enum):
    """MITRE ATT&CK phases mapped to simple stages"""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class TimelineEvent:
    """Single event in attack timeline"""
    stage: AttackStage
    timestamp: datetime
    event_type: str
    details: Dict[str, Any]


class TimelineBuilder:
    """
    Transform raw events into structured attack timeline.
    
    Stages are inferred from:
    - Commands executed
    - Files downloaded
    - Attack types
    - Session patterns
    """
    
    # Command patterns to stage mapping
    STAGE_PATTERNS = {
        AttackStage.INITIAL_ACCESS: ["login", "authentication", "ssh", "telnet"],
        AttackStage.PRIVILEGE_ESCALATION: ["sudo", "su ", "passwd", "shadow", "chmod 4777", "chmod u+s"],
        AttackStage.EXECUTION: ["wget", "curl", "nc ", "/dev/tcp", "python ", "perl ", "bash "],
        AttackStage.COMMAND_AND_CONTROL: ["nc ", "netcat", "socat", "reverse", "backdoor"],
        AttackStage.DISCOVERY: ["ls", "pwd", "whoami", "id", "uname", "cat /etc/", "find "],
        AttackStage.COLLECTION: ["tar ", "zip", "mysqldump", "copy "],
        AttackStage.IMPACT: ["rm -rf", "dd ", "mkfs", "shutdown", "reboot"],
    }
    
    # Attack type patterns
    ATTACK_TYPE_STAGES = {
        "BRUTE_FORCE": AttackStage.INITIAL_ACCESS,
        "COMMAND_EXECUTION": AttackStage.EXECUTION,
        "MALWARE_DOWNLOAD": AttackStage.EXECUTION,
    }
    
    def __init__(self, session_id: str, events: List[Dict[str, Any]]):
        self.session_id = session_id
        self.raw_events = events
    
    def build(self) -> List[TimelineEvent]:
        """Build ordered timeline from raw events"""
        timeline = []
        
        for event in self.raw_events:
            stage = self._infer_stage(event)
            if stage:
                timeline.append(TimelineEvent(
                    stage=stage,
                    timestamp=event.get("timestamp"),
                    event_type=event.get("type", "unknown"),
                    details=event.get("data", {})
                ))
        
        return timeline
    
    def _infer_stage(self, event: Dict[str, Any]) -> Optional[AttackStage]:
        """Infer attack stage from event"""
        event_type = event.get("type", "")
        data = event.get("data", {})
        
        # Check attack type mapping first
        attack_type = data.get("attack_type", "")
        if attack_type in self.ATTACK_TYPE_STAGES:
            return self.ATTACK_TYPE_STAGES[attack_type]
        
        # Check command patterns
        command = data.get("command", "").lower()
        
        for stage, patterns in self.STAGE_PATTERNS.items():
            for pattern in patterns:
                if pattern in command:
                    return stage
        
        return None
    
    def get_story(self) -> Dict[str, Any]:
        """Get human-readable attack story"""
        timeline = self.build()
        
        stages_seen = [e.stage.value for e in timeline]
        unique_stages = list(dict.fromkeys(stages_seen))  # Preserve order, dedupe
        
        story = []
        if "initial_access" in unique_stages:
            story.append("Initial Access")
        if any(s in unique_stages for s in ["execution", "privilege_escalation"]):
            story.append("Execution" if "execution" in unique_stages else "Privilege Escalation")
        if "command_and_control" in unique_stages:
            story.append("Command & Control")
        if "impact" in unique_stages:
            story.append("Impact")
        
        return {
            "timeline": [
                {
                    "stage": e.stage.value,
                    "stage_display": e.stage.name.replace("_", " ").title(),
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "type": e.event_type,
                    "details": e.details
                }
                for e in timeline
            ],
            "story": " → ".join(story) if story else "Unknown",
            "stages": unique_stages
        }