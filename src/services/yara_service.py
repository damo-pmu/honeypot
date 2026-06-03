"""YARA Scanning Service - Match payloads against YARA rules"""
import os
from typing import Dict, Any, List, Optional
from pathlib import Path

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


# Default YARA rules directory
YARA_RULES_DIR = Path(os.getenv("YARA_RULES_DIR", "/app/yara_rules"))


class YaraService:
    """
    Scan payloads with YARA rules.
    Designed for background/sandboxed payload analysis.
    """
    
    # Built-in rules for common patterns
    BUILTIN_RULES = {
        "base64_payload": yara.compile(source="""
rule base64_payload {
    meta:
        description = "Detect base64 encoded content"
        severity = 50
    strings:
        $b64 = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        $b64
}
""") if YARA_AVAILABLE else None,
        "shellcode": yara.compile(source="""
rule shellcode {
    meta:
        description = "Detect potential shellcode"
        severity = 80
    strings:
        $sc1 = { 90 90 90 90 }  // NOP sled
        $sc2 = { 41 58 41 59 41 5a }  // xor rax, rax patterns
    condition:
        uint16(0) != 0x5A4D and $sc1 or $sc2
}
""") if YARA_AVAILABLE else None,
    }
    
    def __init__(self, rules_dir: str = None):
        self.rules_dir = Path(rules_dir or YARA_RULES_DIR)
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self.compiled_rules = {}
    
    def load_rules(self) -> int:
        """Load all YARA rules from directory"""
        if not YARA_AVAILABLE:
            return 0
        
        count = 0
        for rule_file in self.rules_dir.glob("*.yar*"):
            try:
                self.compiled_rules[rule_file.stem] = yara.compile(filepath=str(rule_file))
                count += 1
            except Exception as e:
                print(f"YARA compile error {rule_file}: {e}")
        
        return count
    
    def scan(self, content: bytes, sha256: str = None) -> List[Dict[str, Any]]:
        """Scan payload content against all rules"""
        if not YARA_AVAILABLE:
            return []
        
        matches = []
        
        # Scan with loaded rules
        for rule_name, rule in self.compiled_rules.items():
            try:
                result = rule.match(data=content)
                for match in result:
                    matches.append({
                        "rule": match.rule,
                        "tags": match.tags,
                        "meta": match.meta,
                        "severity": match.meta.get("severity", 0),
                        "sha256": sha256
                    })
            except Exception as e:
                print(f"YARA scan error for {rule_name}: {e}")
        
        return matches
    
    def score(self, matches: List[Dict]) -> int:
        """Calculate YARA-based risk score"""
        return sum(m.get("severity", 0) for m in matches)