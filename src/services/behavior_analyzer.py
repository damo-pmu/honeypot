"""Human vs Bot Behavior Detector - Analyze attacker interaction patterns"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import statistics


class BehaviorAnalyzer:
    """
    Detect if attacker is human or automated bot.
    
    Analyzes:
    - Typing speed (characters per second)
    - Command intervals (pauses between actions)
    - Correction patterns (backspace, retyping)
    - Timing randomness
    """
    
    HUMAN_THRESHOLDS = {
        "typing_speed_min": 2,  # chars/sec
        "typing_speed_max": 20,   # chars/sec
        "avg_interval_min": 1.0,  # seconds
        "avg_interval_max": 30.0,   # seconds
        "correction_ratio_max": 0.3,  # 30% corrections
    }
    
    def __init__(self, session_id: str, events: List[Dict[str, Any]]):
        self.session_id = session_id
        self.events = events
        self.commands = self._extract_commands()
    
    def _extract_commands(self) -> List[Dict]:
        """Extract command events with timestamps"""
        return [
            {
                "command": e.get("data", {}).get("command", ""),
                "timestamp": e.get("timestamp")
            }
            for e in self.events
            if e.get("type") == "command" or e.get("data", {}).get("command")
        ]
    
    def analyze(self) -> Dict[str, Any]:
        """Analyze behavior patterns and return classification"""
        if len(self.commands) < 3:
            return self._result("unknown", 0, "Insufficient data")
        
        scores = {
            "typing_speed": self._analyze_typing_speed(),
            "timing": self._analyze_timing(),
            "corrections": self._analyze_corrections(),
        }
        
        # Weighted score
        weighted = (
            scores["typing_speed"] * 0.3 +
            scores["timing"] * 0.4 +
            scores["corrections"] * 0.3
        )
        
        if weighted >= 0.7:
            actor_type = "human"
            confidence = int(weighted * 100)
        elif weighted <= 0.4:
            actor_type = "bot"
            confidence = int((1 - weighted) * 100)
        else:
            actor_type = "unknown"
            confidence = 50
        
        return self._result(actor_type, confidence, scores)
    
    def _analyze_typing_speed(self) -> float:
        """Analyze character input speed (0=human, 1=bot)"""
        speeds = []
        for cmd in self.commands:
            cmd_text = cmd.get("command", "")
            if len(cmd_text) > 5:  # Min length
                # Estimate: assume ~1 second per command
                speed = len(cmd_text)
                speeds.append(speed)
        
        if not speeds:
            return 0.5
        
        avg_speed = statistics.mean(speeds)
        
        # Very fast (50+ chars/sec) = bot
        if avg_speed > 50:
            return 0.9
        # Normal human range
        if self.HUMAN_THRESHOLDS["typing_speed_min"] <= avg_speed <= self.HUMAN_THRESHOLDS["typing_speed_max"]:
            return 0.2
        
        return 0.5
    
    def _analyze_timing(self) -> float:
        """Analyze timing patterns (0=human, 1=bot)"""
        intervals = self._calculate_intervals()
        
        if len(intervals) < 2:
            return 0.5
        
        avg_interval = statistics.mean(intervals)
        
        # Very regular intervals = bot
        if len(intervals) > 5:
            std_dev = statistics.stdev(intervals)
            if std_dev < 0.5:  # Very consistent
                return 0.8
        
        # Human timing range
        if self.HUMAN_THRESHOLDS["avg_interval_min"] <= avg_interval <= self.HUMAN_THRESHOLDS["avg_interval_max"]:
            return 0.2
        
        return 0.5
    
    def _calculate_intervals(self) -> List[float]:
        """Calculate time intervals between commands"""
        intervals = []
        
        for i in range(1, len(self.commands)):
            ts1 = datetime.fromisoformat(self.commands[i-1]["timestamp"]) if isinstance(self.commands[i-1]["timestamp"], str) else self.commands[i-1]["timestamp"]
            ts2 = datetime.fromisoformat(self.commands[i]["timestamp"]) if isinstance(self.commands[i]["timestamp"], str) else self.commands[i]["timestamp"]
            
            if ts1 and ts2:
                delta = abs((ts2 - ts1).total_seconds())
                intervals.append(delta)
        
        return intervals
    
    def _analyze_corrections(self) -> float:
        """Analyze correction patterns (backspaces, retries)"""
        corrections = 0
        total = 0
        
        for cmd in self.commands:
            cmd_text = cmd.get("command", "")
            if cmd_text:
                total += len(cmd_text)
                corrections += cmd_text.count('\x7f') + cmd_text.count('^?')
        
        if total == 0:
            return 0.5
        
        ratio = corrections / total
        
        # High correction rate = human learning
        if ratio > self.HUMAN_THRESHOLDS["correction_ratio_max"]:
            return 0.2
        
        return 0.7
    
    def _result(self, actor_type: str, confidence: int, scores: Dict = None) -> Dict:
        return {
            "actor_type": actor_type,
            "confidence": confidence,
            "scores": scores or {}
        }