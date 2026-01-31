from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from vibescan.cli import app
import json

runner = CliRunner()

def test_scan_flow_full_integration():
    """
    Test the full scan command flow with mocked external calls but real wiring.
    """
    # Mock NmapRunner result (via VibeScanner)
    # Actually, we mock NmapRunner.scan_common_ports because VibeScanner calls it.
    mock_nmap_ports = {
        "ports": [
            {"port": 80, "service": "http", "version": "Apache/2.4"},
            {"port": 22, "service": "ssh"}
        ]
    }
    
    # Mock HTTP Probe result
    mock_http_probe = {
        "url": "http://example.com",
        "status_code": 200,
        "title": "Example",
        "headers": {"server": "Apache/2.4"},
        "meta_generator": "WordPress 5.0"
    }
    
    # Setup patches
    # We need to patch where they are imported IN cli.py or VibeScanner.
    # vibescan.cli imports NmapRunner, VibeScanner, etc.
    # Instantiate NmapRunner inside scan(), so we should patch the class in vibescan.cli.
    
    with patch("vibescan.cli.NmapRunner") as MockNmapRunner, \
         patch("vibescan.cli.probe_http", return_value=mock_http_probe) as mock_probe, \
         patch("vibescan.cli.fingerprint_from_scan", side_effect=lambda ports, probe: ["apache", "wordpress", "ssh"]) as mock_fp, \
         patch("vibescan.output.formatter.Formatter.info") as mock_info:
        
        # Configure NmapRunner instance
        instance = MockNmapRunner.return_value
        instance.scan_common_ports.return_value = mock_nmap_ports
        
        # Run command with --json to verify full data structure easily
        result = runner.invoke(app, ["scan", "example.com", "--json"])
        
        assert result.exit_code == 0
        
        # Parse JSON
        data = json.loads(result.stdout)
        
        # Verify structure
        assert data["target"] == "example.com"
        assert len(data["ports"]) == 2
        assert data["http_probe"]["title"] == "Example"
        assert "wordpress" in data["fingerprints"]
        
        # CVEs should be present (StubCVEProvider is used directly, not mocked in this test, which is fine as it's deterministic)
        # We expect WordPress CVEs from Stub
        assert len(data["cves"]) > 0
        assert any(c["cve_id"] == "CVE-2021-9999" for c in data["cves"])
        
        # Verify calls
        instance.scan_common_ports.assert_called_with("example.com")
        mock_probe.assert_called()

def test_scan_flow_dry_run():
    """Test dry run skips actual http probing."""
    with patch("vibescan.cli.NmapRunner") as MockNmapRunner, \
         patch("vibescan.cli.probe_http") as mock_probe:
        
        instance = MockNmapRunner.return_value
        instance.scan_common_ports.return_value = {"ports": [{"port": 80, "service": "http"}]}
        
        result = runner.invoke(app, ["scan", "example.com", "--dry-run"])
        
        assert result.exit_code == 0
        mock_probe.assert_not_called()
        # The logic prints detection message but marked skipped
        # Use simple string match or check the formatter calls if we mocked it, 
        # but here we rely on stdout.
        # Actually, since we didn't mock Formatter.info here, it should be in stdout.
        assert "Dry Run - Skipped" in result.stdout
