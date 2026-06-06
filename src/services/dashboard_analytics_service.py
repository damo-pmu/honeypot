"""Advanced Dashboard Analytics Service - Phase 3 Production Ready

Provides expert-level aggregations, insights, and real-time capabilities
for SOC monitoring dashboard.
"""
from datetime import datetime, timezone, timedelta, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_

from src.core.database import (
    AttackerDB, SessionDB, CommandDB, AttackDB, IOCDb, PayloadDB
)
from src.services.statistics_service import StatisticsService


class DashboardAnalyticsService:
    """Expert-level dashboard analytics with advanced aggregations"""
    
    def __init__(self, db: Session):
        self.db = db
        self.stats_service = StatisticsService(db)
    
    def get_threat_heat_map(self, hours: int = 24) -> Dict[str, Any]:
        """Get threat intensity heatmap by time and severity"""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        threats = self.db.query(
            func.date_trunc('hour', AttackDB.timestamp).label('hour'),
            AttackDB.severity,
            func.count(AttackDB.id).label('count')
        ).filter(AttackDB.timestamp >= since).group_by('hour', AttackDB.severity).all()
        
        heatmap = {}
        for threat in threats:
            hour_key = threat.hour.isoformat() if threat.hour else 'unknown'
            severity = threat.severity or 'unknown'
            if hour_key not in heatmap:
                heatmap[hour_key] = {}
            heatmap[hour_key][severity] = threat.count
        
        return {
            "heatmap": heatmap,
            "period_hours": hours,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
    
    def get_attacker_profiles(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get detailed attacker profiles with scoring and behavior patterns"""
        attackers = self.db.query(AttackerDB).order_by(
            AttackerDB.threat_score.desc()
        ).limit(limit).all()
        
        profiles = []
        for attacker in attackers:
            # Count sessions and commands
            session_count = self.db.query(func.count(SessionDB.id)).filter(
                SessionDB.attacker_ip == attacker.ip
            ).scalar() or 0
            
            command_count = self.db.query(func.count(CommandDB.id)).filter(
                CommandDB.attacker_ip == attacker.ip
            ).scalar() or 0
            
            attack_count = self.db.query(func.count(AttackDB.id)).filter(
                AttackDB.attacker_ip == attacker.ip
            ).scalar() or 0
            
            # Get first and last seen
            first_session = self.db.query(SessionDB).filter(
                SessionDB.attacker_ip == attacker.ip
            ).order_by(SessionDB.start_time.asc()).first()
            
            last_session = self.db.query(SessionDB).filter(
                SessionDB.attacker_ip == attacker.ip
            ).order_by(SessionDB.start_time.desc()).first()
            
            profiles.append({
                "ip": attacker.ip,
                "classification": attacker.classification,
                "threat_score": attacker.threat_score,
                "threat_level": attacker.threat_level,
                "reputation": attacker.reputation,
                "country": attacker.country,
                "asn": attacker.asn,
                "session_count": session_count,
                "command_count": command_count,
                "attack_count": attack_count,
                "first_seen": first_session.start_time.isoformat() if first_session else None,
                "last_seen": last_session.start_time.isoformat() if last_session else None,
                "active_threats": [t for t in (attacker.classification or "").split(",")],
                "geoip": attacker.geoip or {}
            })
        
        return profiles
    
    def get_command_patterns(self, limit: int = 50) -> Dict[str, Any]:
        """Identify frequently used commands and suspicious patterns"""
        commands = self.db.query(
            CommandDB.command,
            func.count(CommandDB.id).label('count'),
            func.count(CommandDB.id).filter(CommandDB.flagged == True).label('flagged_count')
        ).group_by(CommandDB.command).order_by(
            func.count(CommandDB.id).desc()
        ).limit(limit).all()
        
        return {
            "patterns": [
                {
                    "command": cmd.command,
                    "usage_count": cmd.count,
                    "suspicious_count": cmd.flagged_count,
                    "risk_score": min(100, (cmd.flagged_count / cmd.count) * 100) if cmd.count > 0 else 0
                }
                for cmd in commands
            ],
            "total_patterns": len(commands)
        }
    
    def get_ioc_summary(self) -> Dict[str, Any]:
        """Get IOC extraction summary and trending indicators"""
        ioc_stats = self.db.query(
            IOCDb.ioc_type,
            func.count(IOCDb.id).label('count'),
            func.avg(IOCDb.confidence).label('avg_confidence'),
            func.max(IOCDb.hit_count).label('max_hits')
        ).group_by(IOCDb.ioc_type).all()
        
        return {
            "by_type": [
                {
                    "type": stat.ioc_type,
                    "count": stat.count,
                    "avg_confidence": float(stat.avg_confidence or 0),
                    "max_hits": stat.max_hits or 0
                }
                for stat in ioc_stats
            ],
            "total_iocs": sum(s.count for s in ioc_stats),
            "high_confidence_iocs": self.db.query(func.count(IOCDb.id)).filter(
                IOCDb.confidence >= 0.8
            ).scalar() or 0
        }
    
    def get_payload_analysis(self, hours: int = 24) -> Dict[str, Any]:
        """Get malware/payload analysis summary with trending"""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        payloads = self.db.query(PayloadDB).filter(
            PayloadDB.first_seen >= since
        ).all()
        
        total_payloads = len(payloads)
        suspicious = sum(1 for p in payloads if p.suspicious_flags and p.suspicious_flags > 0)
        high_entropy = sum(1 for p in payloads if p.entropy and p.entropy > 6)
        
        return {
            "period_hours": hours,
            "total_payloads": total_payloads,
            "suspicious_count": suspicious,
            "suspicious_pct": (suspicious / total_payloads * 100) if total_payloads > 0 else 0,
            "high_entropy_count": high_entropy,
            "by_file_type": self._get_file_type_distribution(payloads),
            "trending": self._get_payload_trending(hours)
        }
    
    def _get_file_type_distribution(self, payloads: List[PayloadDB]) -> Dict[str, int]:
        """Get distribution of file types in payloads"""
        distribution = {}
        for payload in payloads:
            file_type = payload.file_type or "unknown"
            distribution[file_type] = distribution.get(file_type, 0) + 1
        return distribution
    
    def _get_payload_trending(self, hours: int) -> Dict[str, Any]:
        """Get payload trends over time"""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        hourly = self.db.query(
            func.date_trunc('hour', PayloadDB.first_seen).label('hour'),
            func.count(PayloadDB.id).label('count')
        ).filter(PayloadDB.first_seen >= since).group_by('hour').order_by('hour').all()
        
        return {
            "hourly": [
                {"time": h.hour.isoformat() if h.hour else 'unknown', "count": h.count}
                for h in hourly
            ]
        }
    
    def get_attack_taxonomy(self) -> Dict[str, Any]:
        """Get attacks grouped by type/category with metrics"""
        attacks = self.db.query(
            AttackDB.attack_type,
            AttackDB.severity,
            func.count(AttackDB.id).label('count'),
            func.avg(AttackDB.severity).label('avg_severity')
        ).group_by(AttackDB.attack_type, AttackDB.severity).order_by(
            func.count(AttackDB.id).desc()
        ).all()
        
        taxonomy = {}
        for attack in attacks:
            attack_type = attack.attack_type or "unknown"
            if attack_type not in taxonomy:
                taxonomy[attack_type] = {
                    "total": 0,
                    "by_severity": {},
                    "avg_severity": 0
                }
            taxonomy[attack_type]["total"] += attack.count
            taxonomy[attack_type]["by_severity"][attack.severity or "unknown"] = attack.count
        
        return {
            "taxonomy": taxonomy,
            "total_attacks": sum(a["total"] for a in taxonomy.values())
        }
    
    def get_correlation_insights(self, hours: int = 24) -> Dict[str, Any]:
        """Get correlated attack patterns and insights"""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        # Find IPs with multiple session types
        ip_patterns = self.db.query(
            SessionDB.attacker_ip,
            func.count(SessionDB.id).label('session_count'),
            func.array_agg(SessionDB.protocol).label('protocols')
        ).filter(SessionDB.start_time >= since).group_by(
            SessionDB.attacker_ip
        ).having(func.count(SessionDB.id) > 1).all()
        
        correlations = []
        for pattern in ip_patterns:
            protocols = list(set(p for p in pattern.protocols if p))
            if len(protocols) > 1:  # Only if using multiple protocols
                correlations.append({
                    "ip": pattern.attacker_ip,
                    "session_count": pattern.session_count,
                    "protocols_used": protocols,
                    "pattern": "multi_protocol_attacker"
                })
        
        return {
            "insights": correlations,
            "period_hours": hours,
            "correlation_count": len(correlations)
        }


class DashboardExportService:
    """Export dashboard data in multiple formats for reporting"""
    
    def __init__(self, db: Session):
        self.db = db
        self.analytics = DashboardAnalyticsService(db)
    
    def export_threat_report(self, hours: int = 24) -> Dict[str, Any]:
        """Generate comprehensive threat report"""
        return {
            "report_type": "threat_analysis",
            "period_hours": hours,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "heat_map": self.analytics.get_threat_heat_map(hours),
            "profiles": self.analytics.get_attacker_profiles(limit=20),
            "patterns": self.analytics.get_command_patterns(limit=30),
            "iocs": self.analytics.get_ioc_summary(),
            "payloads": self.analytics.get_payload_analysis(hours),
            "attacks": self.analytics.get_attack_taxonomy(),
            "correlations": self.analytics.get_correlation_insights(hours)
        }
    
    def export_csv_headers(self) -> Dict[str, List[str]]:
        """Get CSV export headers for different data types"""
        return {
            "attackers": ["ip", "classification", "threat_score", "country", "asn", "first_seen", "last_seen"],
            "sessions": ["session_id", "attacker_ip", "protocol", "start_time", "end_time", "duration_seconds"],
            "commands": ["command_id", "session_id", "attacker_ip", "command", "timestamp", "flagged"],
            "attacks": ["attack_id", "attack_type", "severity", "timestamp", "attacker_ip", "description"],
            "iocs": ["ioc_id", "ioc_type", "value", "confidence", "source", "first_seen"]
        }
