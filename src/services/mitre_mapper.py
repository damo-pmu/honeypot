"""MITRE ATT&CK Mapper - Map attack behaviors to MITRE techniques"""
from typing import Dict, Any, Optional, List
from enum import Enum


class MitreTactic(str, Enum):
    """MITRE ATT&CK Tactics"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


# Technique mappings - command patterns to MITRE technique IDs
TECHNIQUE_MAPPINGS = {
    # Initial Access
    "SSH_LOGIN": [("T1110.004", "SSH")],
    "TELNET_LOGIN": [("T1110.005", "Telnet")],
    "BRUTE_FORCE": [("T1110", "Brute Force")],
    
    # Execution
    "WGET": [
        ("T1105", "Ingress Tool Transfer"),
        ("T1027.006", "Usage of Downloaded Payload")
    ],
    "CURL": [
        ("T1105", "Ingress Tool Transfer"),
        ("T1027.006", "Usage of Downloaded Payload")
    ],
    
    # Privilege Escalation
    "SUDO": [("T1068", "Exploitation for Privilege Escalation")],
    "SU": [("T1068", "Exploitation for Privilege Escalation")],
    "CHMOD_SUID": [("T1068", "Exploitation for Privilege Escalation")],
    
    # Command & Control
    "NETCAT": [("T1071.001", "Application Layer Protocol: Web Protocols")],
    "REVERSE_SHELL": [
        ("T1071", "Application Layer Protocol"),
        ("T1041", "Exfiltration Over C2 Channel")
    ],
    
    # Discovery
    "WHOAMI": [("T1033", "System Owner/User Discovery")],
    "ID": [("T1033", "System Owner/User Discovery")],
    "UNAME": [("T1033", "System Owner/User Discovery")],
    "LS_ETC": [("T1083", "File and Directory Discovery")],
    "CAT_PASSWD": [("T1087", "Account Discovery")],
    
    # Collection
    "TAR": [("T1560", "Archive Collected Data")],
    "ZIP": [("T1560", "Archive Collected Data")],
    
    # Impact
    "RM_RF": [("T1565", "Data Manipulation")],
    "SHUTDOWN": [("T1562", "Data Destruction")],
}


# Command text patterns
COMMAND_PATTERNS = {
    "wget ": MitreTactic.EXECUTION,
    "curl ": MitreTactic.EXECUTION,
    "nc ": MitreTactic.COMMAND_AND_CONTROL,
    "/dev/tcp": MitreTactic.COMMAND_AND_CONTROL,
    "python -c": MitreTactic.EXECUTION,
    "bash -i": MitreTactic.COMMAND_AND_CONTROL,
    "chmod 4777": MitreTactic.PRIVILEGE_ESCALATION,
    "chmod u+s": MitreTactic.PRIVILEGE_ESCALATION,
    "rm -rf": MitreTactic.IMPACT,
    "dd if=": MitreTactic.IMPACT,
    "cat /etc/passwd": MitreTactic.CREDENTIAL_ACCESS,
    "cat /etc/shadow": MitreTactic.CREDENTIAL_ACCESS,
}


class MitreMapper:
    """
    Map attack behaviors to MITRE ATT&CK techniques.
    Returns tactic + technique for classification and reporting.
    """
    
    def __init__(self, event: Dict[str, Any]):
        self.event = event
    
    def map(self) -> List[Dict[str, str]]:
        """Get MITRE mappings for an event"""
        attack_type = self.event.get("data", {}).get("attack_type", "")
        payload = self.event.get("data", {}).get("payload", "") or ""
        command = self.event.get("data", {}).get("command", "") or ""
        
        results = []
        
        # Check attack type mappings first
        if attack_type in TECHNIQUE_MAPPINGS:
            for tid, technique in TECHNIQUE_MAPPINGS[attack_type]:
                tactic = self._tactic_for_technique(tid)
                results.append({"tactic": tactic, "technique": f"{tid} - {technique}"})
        
        # Check command patterns
        combined = f"{payload} {command}".lower()
        for pattern, tactic in COMMAND_PATTERNS.items():
            if pattern in combined:
                # Find tech for this pattern
                for atk_type, techs in TECHNIQUE_MAPPINGS.items():
                    if atk_type in combined or pattern.split()[0] in combined:
                        for tid, tech in techs:
                            results.append({"tactic": tactic.value, "technique": f"{tid} - {tech}"})
        
        # Deduplicate
        seen = set()
        deduped = []
        for r in results:
            key = r["technique"]
            if key not in seen:
                seen.add(key)
                deduped.append(r)
        
        return deduped
    
    def _tactic_for_technique(self, technique_id: str) -> str:
        """Map technique ID to tactic (rough mapping)"""
        tactic_map = {
            "T1110": MitreTactic.INITIAL_ACCESS,
            "T1105": MitreTactic.COLLECTION,
            "T1068": MitreTactic.PRIVILEGE_ESCALATION,
            "T1071": MitreTactic.COMMAND_AND_CONTROL,
            "T1033": MitreTactic.DISCOVERY,
            "T1083": MitreTactic.DISCOVERY,
            "T1560": MitreTactic.COLLECTION,
        }
        
        # Extract tactic from first part of technique
        base_id = technique_id.split(".")[0]
        return tactic_map.get(base_id, MitreTactic.EXECUTION).value