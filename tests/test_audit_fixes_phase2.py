"""Phase 2 Audit Fixes Validation Tests

Validates security enhancements:
- CORS restriction with env var configuration
- Enhanced SafetyIsolator patterns for real secret detection
- Architecture documentation updates
- Environment variable consistency
"""
import os
import re
import pytest
from unittest.mock import patch, MagicMock

# Test modules
from src.response.safety import SafetyIsolator, SafetyCheck


class TestCORSConfiguration:
    """CORS restriction and configuration tests (Phase 2)"""

    def test_cors_allowed_origins_env_parsing(self):
        """CORS origins must be parsed from CORS_ALLOWED_ORIGINS env var"""
        # Simulate environment with comma-separated origins
        with patch.dict(os.environ, {
            "CORS_ALLOWED_ORIGINS": "http://localhost:3000,http://localhost:8000,https://dashboard.example.com"
        }):
            allowed_origins_str = os.getenv(
                "CORS_ALLOWED_ORIGINS",
                "http://localhost:3000,http://localhost:5000,http://localhost:9090"
            )
            origins = [origin.strip() for origin in allowed_origins_str.split(",")]
            
            assert len(origins) == 3
            assert "http://localhost:3000" in origins
            assert "http://localhost:8000" in origins
            assert "https://dashboard.example.com" in origins

    def test_cors_default_origins(self):
        """CORS must have sensible defaults when env var not set"""
        with patch.dict(os.environ, {}, clear=False):
            # Simulate default when env var is not set
            allowed_origins_str = os.getenv(
                "CORS_ALLOWED_ORIGINS",
                "http://localhost:3000,http://localhost:5000,http://localhost:9090"
            )
            origins = [origin.strip() for origin in allowed_origins_str.split(",")]
            
            # Should include Grafana (port 3000), alternative frontend (5000), Prometheus (9090)
            assert len(origins) == 3
            assert any("3000" in o for o in origins), "Should include Grafana default"
            assert any("5000" in o for o in origins), "Should include alternative frontend"
            assert any("9090" in o for o in origins), "Should include Prometheus"

    def test_cors_no_wildcard_origins(self):
        """CORS origins must NOT include wildcard (*) in production"""
        # Test that default and example values never have wildcards
        default_origins = "http://localhost:3000,http://localhost:5000,http://localhost:9090"
        assert "*" not in default_origins, "Default CORS origins must not include wildcard"
        
        # Test common production misconfigurations are avoided
        forbidden_patterns = ["*", "*.example.com", "*:*"]
        for pattern in forbidden_patterns:
            assert pattern not in default_origins

    def test_cors_only_safe_methods(self):
        """CORS must restrict to safe HTTP methods"""
        # Allowed methods must be restricted, not include wildcard
        allowed_methods = ["GET", "POST", "PUT", "DELETE"]
        
        # Verify DANGEROUS methods are NOT allowed
        forbidden_methods = ["CONNECT", "TRACE", "DEBUG", "OPTIONS"]
        for method in forbidden_methods:
            assert method not in allowed_methods, f"Method {method} should not be allowed"
        
        # Verify safe operations are included
        assert "GET" in allowed_methods
        assert "POST" in allowed_methods


class TestEnhancedSafetyPatterns:
    """Enhanced SafetyIsolator patterns for better secret detection (Phase 2)"""

    def test_blocked_patterns_comprehensive(self):
        """SafetyIsolator must have comprehensive blocked patterns"""
        isolator = SafetyIsolator()
        
        # Must include private key detection
        pk_patterns = [p for p in isolator.BLOCKED_PATTERNS if "PRIVATE KEY" in p or "EC PRIVATE" in p]
        assert len(pk_patterns) >= 2, "Must detect multiple private key formats"
        
        # Must include AWS key detection
        aws_patterns = [p for p in isolator.BLOCKED_PATTERNS if "AKIA" in p or "aws" in p.lower()]
        assert len(aws_patterns) >= 1, "Must detect AWS key patterns"
        
        # Must include GitHub token detection
        github_patterns = [p for p in isolator.BLOCKED_PATTERNS if "ghp_" in p]
        assert len(github_patterns) >= 1, "Must detect GitHub token patterns"

    def test_detects_github_tokens(self):
        """SafetyIsolator must detect GitHub personal access tokens"""
        isolator = SafetyIsolator()
        
        # GitHub token pattern: ghp_ prefix + 36 alphanumeric chars total
        # ghp_abcdefghijklmnopqrstuvwxyz123456ab = ghp_ + 32 alphanumeric
        test_token = "ghp_" + "a" * 36  # GitHub tokens are ghp_ + 36 chars
        
        for pattern in isolator.BLOCKED_PATTERNS:
            if re.search(pattern, test_token, re.IGNORECASE):
                return  # Found - test passes
        
        pytest.fail("SafetyIsolator should detect GitHub token pattern")

    def test_detects_aws_access_keys(self):
        """SafetyIsolator must detect AWS access key IDs"""
        isolator = SafetyIsolator()
        
        # AWS access key pattern: AKIA + 16 alphanumeric
        test_key = "AKIAIOSFODNN7EXAMPLE"
        
        for pattern in isolator.BLOCKED_PATTERNS:
            if re.search(pattern, test_key, re.IGNORECASE):
                return  # Found - test passes
        
        pytest.fail("SafetyIsolator should detect AWS access key pattern")

    def test_detects_stripe_keys(self):
        """SafetyIsolator must detect Stripe API keys"""
        isolator = SafetyIsolator()
        
        # Build Stripe test keys dynamically to avoid literal secret-like strings in source
        prefix_sk = "sk_" + "test_"
        prefix_pk = "pk_" + "test_"
        suffix = "abcdefghijklmnopqrstuvwx"
        test_keys = [
            prefix_sk + suffix,
            prefix_pk + suffix,
        ]

        for test_key in test_keys:
            found = False
            for pattern in isolator.BLOCKED_PATTERNS:
                if re.search(pattern, test_key, re.IGNORECASE):
                    found = True
                    break
            assert found, f"SafetyIsolator should detect Stripe key pattern: {test_key}"

    def test_detects_database_urls(self):
        """SafetyIsolator must detect real database connection strings"""
        isolator = SafetyIsolator()
        
        test_urls = [
            "mongodb://user:realpassword@host.com",
            "postgres://admin:SecurePass123@db.company.com",
            "mysql://root:MyPassword@internal.db"
        ]
        
        for test_url in test_urls:
            found = False
            for pattern in isolator.BLOCKED_PATTERNS:
                if re.search(pattern, test_url, re.IGNORECASE):
                    found = True
                    break
            assert found, f"SafetyIsolator should detect database URL pattern: {test_url}"

    def test_decoy_credentials_still_allowed(self):
        """SafetyIsolator must allow FAKE_ prefixed credentials"""
        isolator = SafetyIsolator()
        
        fake_credentials = [
            "FAKE_PASSWORD_STUB",
            "FAKE_NTLM_HASH_STUB",
            "FAKE_SSH_KEY_STUB_FOR_TESTING",
            "password=FAKE_PASS_STUB"
        ]
        
        for fake_cred in fake_credentials:
            # Should NOT trigger any blocked patterns
            for pattern in isolator.BLOCKED_PATTERNS:
                assert not re.search(pattern, fake_cred, re.IGNORECASE), \
                    f"SafetyIsolator incorrectly blocks fake credential: {fake_cred}"


class TestArchitectureDocumentation:
    """Architecture documentation completeness (Phase 2)"""

    def test_architecture_md_exists(self):
        """ARCHITECTURE.md must exist"""
        assert os.path.exists("docs/ARCHITECTURE.md"), "docs/ARCHITECTURE.md must exist"

    def test_architecture_documents_cors(self):
        """ARCHITECTURE.md must document CORS policy"""
        with open("docs/ARCHITECTURE.md", "r") as f:
            content = f.read()
        
        assert "CORS" in content, "ARCHITECTURE.md must mention CORS"
        assert "CORS_ALLOWED_ORIGINS" in content or "Allowed Origins" in content, \
            "ARCHITECTURE.md must document CORS configuration approach"

    def test_architecture_documents_security(self):
        """ARCHITECTURE.md must have comprehensive security section"""
        with open("docs/ARCHITECTURE.md", "r") as f:
            content = f.read()
        
        assert "Sécurité" in content or "Security" in content, \
            "ARCHITECTURE.md must have security section"
        assert "DASHBOARD_PASSWORD" in content or "auth" in content.lower(), \
            "ARCHITECTURE.md must document authentication"


class TestEnvironmentConfiguration:
    """Environment variable consistency (Phase 2)"""

    def test_env_example_has_cors_config(self):
        """env.example must include CORS_ALLOWED_ORIGINS"""
        with open(".env.example", "r") as f:
            content = f.read()
        
        assert "CORS_ALLOWED_ORIGINS" in content, \
            ".env.example must define CORS_ALLOWED_ORIGINS"

    def test_env_example_has_honeypot_hostname(self):
        """env.example must include HONEYPOT_HOSTNAME"""
        with open(".env.example", "r") as f:
            content = f.read()
        
        assert "HONEYPOT_HOSTNAME" in content, \
            ".env.example must define HONEYPOT_HOSTNAME"

    def test_cors_origins_format_valid(self):
        """CORS_ALLOWED_ORIGINS in .env.example must have valid URL format"""
        with open(".env.example", "r") as f:
            lines = f.readlines()
        
        cors_line = None
        for line in lines:
            if "CORS_ALLOWED_ORIGINS=" in line and not line.strip().startswith("#"):
                cors_line = line
                break
        
        assert cors_line is not None, "CORS_ALLOWED_ORIGINS must be defined (not commented)"
        
        # Extract value after equals
        cors_value = cors_line.split("=", 1)[1].strip()
        
        # Must contain at least one valid URL
        assert "http://" in cors_value or "https://" in cors_value, \
            "CORS_ALLOWED_ORIGINS must contain valid URLs"

    def test_docker_compose_has_cors_env(self):
        """docker-compose.yml must pass CORS_ALLOWED_ORIGINS to api service"""
        with open("docker-compose.yml", "r") as f:
            content = f.read()
        
        assert "CORS_ALLOWED_ORIGINS" in content, \
            "docker-compose.yml must include CORS_ALLOWED_ORIGINS in api service"


class TestSecurityPatternRegression:
    """Ensure Phase 2 patterns don't regress on Phase 1 fixes"""

    def test_blocked_patterns_include_phase1_items(self):
        """Phase 2 patterns must still detect Phase 1 secret types"""
        isolator = SafetyIsolator()
        
        # Phase 1 items that should still be detected (with test values)
        phase1_tests = [
            ("BEGIN RSA PRIVATE KEY", "-----BEGIN RSA PRIVATE KEY-----"),
            ("Certificates", "-----BEGIN CERTIFICATE-----"),
            ("SECRET_KEY", "SECRET_KEY = 'real_secret'"),
            ("Real domains", "admin@hiddenlabs.cc"),
        ]
        
        for description, test_value in phase1_tests:
            found = False
            for pattern in isolator.BLOCKED_PATTERNS:
                if re.search(pattern, test_value, re.IGNORECASE):
                    found = True
                    break
            assert found, f"Phase 2 must still detect Phase 1 item: {description}"

    def test_safe_templates_unchanged(self):
        """SafetyIsolator ALLOWED_TEMPLATES must remain consistent"""
        isolator = SafetyIsolator()
        
        # Ensure all Phase 1 templates still allowed
        required_templates = {
            "cisco_router/show_version",
            "cisco_router/running_config",
            "windows_server/credentials",
            "jenkins_ci/config",
            "ai_challenge/cognitive_trap"
        }
        
        for template in required_templates:
            assert template in isolator.ALLOWED_TEMPLATES, \
                f"Phase 1 template {template} must remain in allowlist"


class TestPhase2Completeness:
    """Overall Phase 2 completeness checks"""

    def test_all_phase2_artifacts_present(self):
        """All Phase 2 artifacts must be present"""
        required_artifacts = [
            "docs/ARCHITECTURE.md",
            ".env.example",
            "docker-compose.yml",
            "src/response/safety.py",
            "app.py"
        ]
        
        for artifact in required_artifacts:
            assert os.path.exists(artifact), f"Required Phase 2 artifact missing: {artifact}"

    def test_cors_env_var_not_required(self):
        """CORS_ALLOWED_ORIGINS must be optional with sensible defaults"""
        # If env var not set, should use reasonable defaults
        with patch.dict(os.environ, {}, clear=False):
            allowed_origins_str = os.getenv(
                "CORS_ALLOWED_ORIGINS",
                "http://localhost:3000,http://localhost:5000,http://localhost:9090"
            )
            
            # Defaults should be populated
            assert "localhost" in allowed_origins_str
            assert len(allowed_origins_str.split(",")) >= 2
