"""Tests for Response Engine (Feature 8)"""
import pytest
from datetime import datetime
from src.response.router import (
    decide_response, ResponseType, ResponseDecision, get_response_content
)
from src.response.fake_env import (
    generate_cisco_decoy, generate_windows_decoy, generate_jenkins_decoy
)
from src.response.safety import SafetyIsolator, SafetyCheck


class TestResponseRouter:
    """Test response decision logic"""
    
    def test_decide_bot_response(self):
        """BOT gets fake Cisco environment"""
        result = decide_response("sess1", "10.0.0.1", "BOT", 0.5, 1)
        assert result.response_type == ResponseType.FAKE_ENVIRONMENT
        assert result.template_name == "cisco_router/show_version"
    
    def test_decide_ai_response(self):
        """AI agent gets challenge response"""
        result = decide_response("sess2", "10.0.0.2", "POSSIBLE_AI_AGENT", 0.8, 5)
        assert result.response_type == ResponseType.CHALLENGE_RESPONSE
        assert "cognitive" in result.template_name or "challenge" in result.template_name
    
    def test_decide_script_kiddie_response(self):
        """Script kiddie gets visible credentials"""
        result = decide_response("sess3", "10.0.0.3", "SCRIPT_KIDDIE", 0.3, 2)
        assert result.response_type == ResponseType.CREDENTIAL_LEAK
    
    def test_decide_max_interactions_terminate(self):
        """Session terminates after max interactions"""
        result = decide_response("sess4", "10.0.0.4", "BOT", 0.5, 25)
        assert result.response_type == ResponseType.TERMINATE
    
    def test_get_response_content(self):
        """Get template content"""
        content = get_response_content("cisco_router/show_version")
        assert content is not None
        assert "Cisco IOS" in content


class TestFakeEnvironment:
    """Test decoy environment generation"""
    
    def test_cisco_decoy_generation(self):
        """Generate Cisco router decoy"""
        decoy = generate_cisco_decoy()
        assert decoy.template_name == "cisco_router"
        assert decoy.os_type == "Cisco IOS"
        assert len(decoy.files) > 0
        # Files have paths like /show/version, /show/running-config
        assert "show" in decoy.files[0].path or "running" in decoy.files[0].path
    
    def test_windows_decoy_generation(self):
        """Generate Windows server decoy"""
        decoy = generate_windows_decoy()
        assert decoy.template_name == "windows_server"
        assert decoy.os_type == "Windows Server 2019"
    
    def test_jenkins_decoy_generation(self):
        """Generate Jenkins CI decoy"""
        decoy = generate_jenkins_decoy()
        assert decoy.template_name == "jenkins_ci"
        assert decoy.os_type == "Linux (Ubuntu)"


class TestSafetyIsolator:
    """Test safety validation"""
    
    def test_safe_content_passes(self):
        """Safe content passes validation"""
        isolator = SafetyIsolator()
        check = isolator.validate_response("Cisco IOS version", "cisco_router/show_version")
        assert check.safe == True
    
    def test_blocked_real_domain(self):
        """Real domain gets blocked"""
        isolator = SafetyIsolator()
        check = isolator.validate_response(
            "contact us at admin@hiddenlabs.cc", 
            "cisco_router/show_version"
        )
        assert check.safe == False
    
    def test_blocked_private_key(self):
        """Private key pattern blocked"""
        isolator = SafetyIsolator()
        check = isolator.validate_response(
            "-----BEGIN RSA PRIVATE KEY----",
            "any_template"
        )
        assert check.safe == False
    
    def test_unknown_template_blocked(self):
        """Non-allowlisted template blocked"""
        isolator = SafetyIsolator()
        check = isolator.validate_response("content", "unknown/template")
        assert check.safe == False
    
    def test_dangerous_command_blocked(self):
        """Dangerous commands blocked"""
        isolator = SafetyIsolator()
        assert isolator.sanitize_command("rm -rf /") is None
        assert isolator.sanitize_command("cat /etc/shadow") is None
        assert isolator.sanitize_command("ls -la") == "ls -la"  # Safe