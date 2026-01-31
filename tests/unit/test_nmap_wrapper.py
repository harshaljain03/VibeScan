from unittest.mock import MagicMock
from vibescan.core.nmap_wrapper import NmapRunner

def test_scan_common_ports_subprocess():
    """Test scan_common_ports using subprocess simulation."""
    # Fake runner output
    # This simulates output from: nmap -sS -Pn -F example.com
    nmap_output = """
Starting Nmap 7.80 ( https://nmap.org ) at 2021-08-01 12:00 UTC
Nmap scan report for example.com (93.184.216.34)
Host is up (0.010s latency).
Not shown: 98 filtered ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
Nmap done: 1 IP address (1 host up) scanned in 1.45 seconds
"""
    
    # Fake runner
    mock_runner = MagicMock()
    mock_runner.return_value.stdout = nmap_output
    
    runner = NmapRunner(runner=mock_runner)
    result = runner.scan_common_ports("example.com")
    
    # Check that runner was called with expected args
    mock_runner.assert_called_once()
    args = mock_runner.call_args[0][0]
    expected_cmd = ["nmap", "-sV", "-Pn", "-F", "example.com"]
    assert args == expected_cmd
    
    # Check parsing
    assert result["target"] == "example.com"
    assert len(result["ports"]) == 3
    
    p22 = next(p for p in result["ports"] if p["port"] == 22)
    assert p22["service"] == "ssh"
    assert p22["proto"] == "tcp"
    
    p80 = next(p for p in result["ports"] if p["port"] == 80)
    assert p80["service"] == "http"

def test_scan_common_ports_python_nmap():
    """Test scan_common_ports using mocked python-nmap."""
    # Mock nmap module
    mock_nmap_module = MagicMock()
    mock_scanner = mock_nmap_module.PortScanner.return_value
    
    # Mock scan data access (mimic nm[host][proto][port]...)
    # This is tricky because python-nmap uses __getitem__ heavily.
    # Structure: nm['127.0.0.1']['tcp'][22]
    
    target_ip = "127.0.0.1"
    mock_scanner.all_hosts.return_value = [target_ip]
    mock_scanner.all_protocols.return_value = ['tcp'] # This needs to be on the host object
    
    # We need: nm[target_ip].all_protocols() -> ['tcp']
    # And: nm[target_ip]['tcp'][21] -> dict
    
    host_mock = MagicMock()
    host_mock.all_protocols.return_value = ["tcp"]
    host_mock.__getitem__.return_value = {
        21: {'state': 'open', 'name': 'ftp', 'product': 'vsftpd', 'version': '3.0.3'},
        80: {'state': 'open', 'name': 'http', 'product': 'nginx', 'version': ''}
    }
    
    # Setup the __getitem__ chain on Scanner to return host_mock
    mock_scanner.__getitem__.return_value = host_mock
    
    # Instantiate wrapper
    runner = NmapRunner(nmap_module=mock_nmap_module)
    result = runner.scan_common_ports("example.com")
    
    # Assertions
    mock_scanner.scan.assert_called_with(hosts="example.com", arguments='-sV -Pn -F')
    
    assert result["target"] == "example.com"
    assert len(result["ports"]) == 2
    
    p21 = next(p for p in result["ports"] if p["port"] == 21)
    assert p21["service"] == "ftp"
    # Full version = product + version
    assert "vsftpd 3.0.3" in p21["version"]

def test_parse_nmap_output_edge_cases():
    """Test parser with tricky output."""
    output = """
Nmap scan report for foo.bar
PORT STATE SERVICE VERSION
1/tcp open tcpmux
"""
    runner = NmapRunner()
    result = runner._parse_nmap_output(output)
    
    assert result["target"] == "foo.bar"
    assert len(result["ports"]) == 1
    assert result["ports"][0]["service"] == "tcpmux"
    
    # Test version parsing
    output_version = """
Nmap scan report for 1.1.1.1
PORT   STATE SERVICE VERSION
53/tcp open  domain  nlnetlabs-nsd
"""
    result = runner._parse_nmap_output(output_version)
    assert result["target"] == "1.1.1.1"
    assert result["ports"][0]["version"] == "nlnetlabs-nsd"
