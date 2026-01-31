from vibescan.core.fingerprint import fingerprint_from_scan

def test_fingerprint_ssh_detected():
    """Test detection of SSH from ports."""
    ports = [{"port": 22, "service": "ssh", "version": "OpenSSH"}]
    components = fingerprint_from_scan(ports)
    assert "ssh" in components

def test_fingerprint_apache_detected():
    """Test detection of Apache from headers."""
    ports = [{"port": 80, "service": "http"}]
    probe = {
        "headers": {"server": "Apache/2.4.41 (Ubuntu)"},
        "meta_generator": None
    }
    components = fingerprint_from_scan(ports, probe)
    assert "apache" in components

def test_fingerprint_wordpress_detected():
    """Test detection of WordPress from meta generator."""
    ports = [{"port": 443, "service": "https"}]
    probe = {
        "headers": {"server": "nginx"},
        "meta_generator": "WordPress 6.0"
    }
    components = fingerprint_from_scan(ports, probe)
    assert "wordpress" in components
    assert "nginx" in components

def test_fingerprint_multiple():
    """Test multiple components."""
    ports = [{"port": 22, "service": "ssh"}]
    probe = {
        "headers": {"server": "Apache"},
        "meta_generator": "Drupal 9"
    }
    components = fingerprint_from_scan(ports, probe)
    assert "ssh" in components
    assert "apache" in components
    assert "drupal" in components
