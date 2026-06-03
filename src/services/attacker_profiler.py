"""Attacker Profiling Service - Classify attacker infrastructure"""
from typing import Dict, Any, Optional
from enum import Enum


class InfrastructureType(str, Enum):
    TOR = "tor"
    VPN = "vpn"
    CLOUD = "cloud"
    HOSTING = "hosting"
    RESIDENTIAL = "residential"
    UNKNOWN = "unknown"


# Known infrastructure patterns
TOR_EXIT_IPS = set()  # Populated from torproject.org
VPN_PREFIXES = ["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21."]
CLOUD_ASNS = [14618, 16509, 20489, 14061, 20489]  # AWS, GCP, Azure, DigitalOcean
HOSTING_KEYWORDS = ["ovh", "kimsufi", "hetzner", "digitalocean", "linode", "vultr", "cloudflare"]


class AttackerProfiler:
    """
    Profile attacker infrastructure and classify connection type.
    
    Uses GeoIP + ASN data to determine:
    - TOR exit node
    - VPN/proxy
    - Cloud provider
    - Hosting provider
    - Residential IP
    """
    
    def __init__(self, ip: str, geoip_data: Dict[str, Any] = None):
        self.ip = ip
        self.geoip = geoip_data or {}
    
    def profile(self) -> Dict[str, Any]:
        """Get attacker profile"""
        infrastructure = self._classify_infrastructure()
        risk_level = self._calculate_risk(infrastructure)
        
        return {
            "ip": self.ip,
            "infrastructure": infrastructure.value,
            "risk_level": risk_level,
            "country": self.geoip.get("country", "Unknown"),
            "asn": self.geoip.get("asn", None),
            "provider": self.geoip.get("org", "Unknown"),
        }
    
    def _classify_infrastructure(self) -> InfrastructureType:
        """Classify infrastructure type based on IP/ASN patterns"""
        # Check if TOR exit (from enrichment)
        if self.geoip.get("tags", {}).get("tor"):
            return InfrastructureType.TOR
        
        asn = self.geoip.get("asn", 0)
        org = (self.geoip.get("org") or "").lower()
        
        # Check cloud providers
        if asn in CLOUD_ASNS:
            return InfrastructureType.CLOUD
        
        # Check hosting providers
        for keyword in HOSTING_KEYWORDS:
            if keyword in org:
                return InfrastructureType.HOSTING
        
        # Check VPN patterns
        if any(self.ip.startswith(prefix.rstrip(".")) for prefix in VPN_PREFIXES):
            return InfrastructureType.VPN
        
        return InfrastructureType.RESIDENTIAL
    
    def _calculate_risk(self, infra_type: InfrastructureType) -> str:
        """Calculate risk level based on infrastructure"""
        risk_map = {
            InfrastructureType.TOR: "high",
            InfrastructureType.VPN: "medium",
            InfrastructureType.CLOUD: "low",
            InfrastructureType.HOSTING: "medium",
            InfrastructureType.RESIDENTIAL: "high",
            InfrastructureType.UNKNOWN: "unknown"
        }
        return risk_map.get(infra_type, "unknown")