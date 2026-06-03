"""Payload Analysis Service - Download, analyze and classify malware payloads"""
import hashlib
import math
import os
import re
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path

try:
    import magic  # python-magic for file type detection
except ImportError:
    magic = None


class PayloadAnalyzer:
    """
    Analyze downloaded payloads in sandboxed environment.
    
    Extracts: SHA256, MD5, Entropy, Strings, File Type
    Detects: wget, curl, tftp, scp download patterns
    """
    
    DOWNLOAD_PATTERNS = [
        r'(?:wget|curl)\s+([^\s]+)',
        r'(?:tftp\s+-r\s+([^\s]+))',
        r'(?:scp\s+([^\s]+))',
    ]
    
    def __init__(self, payload_dir: str = "/app/payloads"):
        self.payload_dir = Path(payload_dir)
        self.payload_dir.mkdir(parents=True, exist_ok=True)
    
    def extract_url(self, text: str) -> Optional[str]:
        """Extract download URL from command/output"""
        for pattern in self.DOWNLOAD_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def analyze_content(self, content: bytes) -> Dict[str, Any]:
        """Analyze raw payload content"""
        if not content:
            return {}
        
        # Hash calculations
        sha256 = hashlib.sha256(content).hexdigest()
        md5 = hashlib.md5(content).hexdigest()
        
        # Entropy (high entropy = encrypted/packed)
        entropy = self._calculate_entropy(content)
        
        # File type detection
        file_type = self._detect_file_type(content)
        
        # Strings extraction
        strings = self._extract_strings(content)
        
        # Suspicious patterns
        suspicious = self._find_suspicious_patterns(content)
        
        return {
            "sha256": sha256,
            "md5": md5,
            "size": len(content),
            "entropy": round(entropy, 2),
            "file_type": file_type,
            "strings": strings[:50],  # Top 50 strings
            "suspicious": suspicious,
            "packed": entropy > 7.5,  # Likely obfuscated
        }
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p = data.count(bytes([x])) / len(data)
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _detect_file_type(self, content: bytes) -> str:
        """Detect file type using magic bytes or content sniffing"""
        if magic:
            try:
                return magic.from_buffer(content[:1024], mime=True)
            except:
                pass
        
        # Fallback: simple signature detection
        if content[:4] == b'\x7fELF':
            return "application/x-executable-linux"
        if content[:2] == b'MZ':
            return "application/x-dosexec"
        if content[:4] == b'\xca\xfe\xba\xbe':
            return "application/x-java-applet"
        
        return "application/octet-stream"
    
    def _extract_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        """Extract printable strings from binary"""
        strings = []
        current = b''
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current += bytes([byte])
            else:
                if len(current) >= min_len:
                    strings.append(current.decode('ascii', errors='ignore'))
                current = b''
        
        if len(current) >= min_len:
            strings.append(current.decode('ascii', errors='ignore'))
        
        return strings
    
    def _find_suspicious_patterns(self, data: bytes) -> List[str]:
        """Find suspicious patterns in payload"""
        text = data.decode('utf-8', errors='ignore').lower()
        suspicious = []
        
        patterns = {
            'powershell': 'PowerShell',
            'base64': 'Base64 encoding',
            'xor_loop': 'XOR obfuscation',
            'anti_debug': 'Anti-debug',
            'process_hollowing': 'Process injection',
        }
        
        if 'powershell' in text or 'ps1' in text:
            suspicious.append("PowerShell")
        if 'frombase64' in text or 'base64_decode' in text:
            suspicious.append("Base64 encoding")
        if 'xor' in text and ('byte' in text or 'char' in text):
            suspicious.append("XOR obfuscation")
        if 'isdebuggerpresent' in text or 'checkremote debugger' in text:
            suspicious.append("Anti-debug")
        
        return suspicious
    
    def save_payload(self, sha256: str, content: bytes) -> str:
        """Save payload to sandbox directory"""
        filename = f"{sha256[:16]}.bin"
        filepath = self.payload_dir / filename
        
        if not filepath.exists():
            filepath.write_bytes(content)
        
        return str(filepath)