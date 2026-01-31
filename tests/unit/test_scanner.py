from unittest.mock import MagicMock
from vibescan.core.scanner import VibeScanner

def test_run_scan_narrates_and_scans():
    """Test that run_scan narrates steps and calls port scanner."""
    # Mock NmapRunner
    mock_runner = MagicMock()
    port_results = {
        "target": "simulated.target",
        "ports": [{"port": 80, "service": "http"}]
    }
    mock_runner.scan_common_ports.return_value = port_results
    
    # Mock Formatter
    mock_formatter = MagicMock()
    
    # Instantiate Scanner
    scanner = VibeScanner(nmap_runner=mock_runner, formatter=mock_formatter)
    
    # Run scan
    results = scanner.run_scan("simulated.target")
    
    # Assert Narration
    mock_formatter.info.assert_called_with("[1/4] Scanning common ports")
    
    # Assert Scan Call
    mock_runner.scan_common_ports.assert_called_with("simulated.target")
    
    # Assert Results
    assert results["target"] == "simulated.target"
    assert len(results["ports"]) == 1
    assert results["ports"][0]["port"] == 80
