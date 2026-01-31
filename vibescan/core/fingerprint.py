from typing import List, Dict, Optional, Any

def fingerprint_from_scan(ports: List[Dict[str, Any]], http_probe: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Identify probable components based on scan results and HTTP probe data.
    
    :param ports: List of port dictionaries (from NmapRunner).
    :param http_probe: Dictionary of HTTP probe results (from WebProbe).
    :return: List of identified component names.
    """
    components = set()
    
    # Analyze ports
    for port in ports:
        service = port.get("service", "").lower()
        version = port.get("version", "").lower()
        
        if "ssh" in service:
            components.add("ssh")
        if "http" in service or "https" in service:
            # We don't add "http" as a component usually, but if the task implies "apache" etc.
            pass
            
    # Analyze HTTP probe
    if http_probe:
        headers = http_probe.get("headers", {})
        
        # Check Server header
        server = headers.get("server", "").lower()
        if "apache" in server:
            components.add("apache")
        if "nginx" in server:
            components.add("nginx")
            
        # Check meta generator
        generator = http_probe.get("meta_generator", "")
        if generator:
            gen_lower = generator.lower()
            if "wordpress" in gen_lower:
                components.add("wordpress")
            if "drupal" in gen_lower:
                components.add("drupal")
            if "joomla" in gen_lower:
                components.add("joomla")

    return sorted(list(components))
