import json
from unittest.mock import MagicMock
from vibescan.output.formatter import Formatter

def test_info_prints_to_console():
    """Test that info() calls Console.print."""
    formatter = Formatter()
    formatter.console = MagicMock()
    
    formatter.info("Test message")
    formatter.console.print.assert_called_with("Test message")

def test_format_report_json():
    """Test format_report_json returns valid JSON."""
    formatter = Formatter()
    report = {
        "target": "example.com",
        "ports": [{"port": 80, "service": "http"}]
    }
    
    json_str = formatter.format_report_json(report)
    data = json.loads(json_str)
    
    assert data["target"] == "example.com"
    assert len(data["ports"]) == 1
    assert data["ports"][0]["service"] == "http"

def test_format_report_human():
    """Test format_report_human returns readable string."""
    formatter = Formatter()
    report = {
        "target": "example.com",
        "ports": [
            {"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH 8.2"},
            {"port": 80, "proto": "tcp", "service": "http", "version": ""}
        ],
        "fingerprints": ["ssh", "apache"],
        "cves": [{"cve_id": "CVE-2021-1234", "summary": "Bad vuln", "cvss": 9.8}]
    }
    
    human_str = formatter.format_report_human(report)
    
    assert "Scan Report for: example.com" in human_str
    assert "PORT" in human_str
    assert "SERVICE" in human_str
    assert "Detected Components: ssh, apache" in human_str
    assert "Vulnerabilities (1 found):" in human_str
    assert "CVE-2021-1234 (CVSS: 9.8)" in human_str
    
    # Check for content presence
    assert "22" in human_str
    assert "ssh" in human_str
    assert "OpenSSH 8.2" in human_str
    assert "80" in human_str
    assert "http" in human_str
