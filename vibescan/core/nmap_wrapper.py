import subprocess
import re
from typing import Optional, Dict, List, Any, Callable

class NmapRunner:
    def __init__(self, nmap_module: Any = None, runner: Optional[Callable] = None):
        """
        Initialize the NmapRunner.
        
        :param nmap_module: Optional python-nmap module for scanning.
        :param runner: Optional callable to execute subprocess commands. 
                       Should accept a list of arguments and return a CompletedProcess-like object 
                       (with .stdout attribute).
        """
        self.nmap_module = nmap_module
        self.runner = runner

    def scan_common_ports(self, target: str) -> Dict[str, Any]:
        """
        Scan common ports on the target.
        
        :param target: The target IP or hostname.
        :return: A dictionary containing the scan results.
        """
        if self.nmap_module:
            try:
                nm = self.nmap_module.PortScanner()
                # Run the scan. Note: arguments must map to the subprocess command intent roughly.
                # The CLI usually does -sS -Pn -F. python-nmap: nm.scan('127.0.0.1', '22-443') 
                # or nm.scan(hosts='...', arguments='-sS -Pn -F')
                nm.scan(hosts=target, arguments='-sV -Pn -F')
                
                # Convert python-nmap result to our format
                # python-nmap result structure:
                # { 'scan': { '127.0.0.1': { 'tcp': { 22: {'state': 'open', 'name': 'ssh', 'product': '', 'version': ''} } } } }
                
                # Check if target is in scan results
                # nm[target] might raise KeyError if not found or no results
                
                return self._parse_python_nmap_result(nm, target)
            except Exception as e:
                # In case of error (e.g. nmap binary missing), fall through or return error?
                # For now, let's just return minimal error info or raise.
                # Implementation choice: return empty results with error note ideally, 
                # but spec says return structured dict.
                return {"target": target, "ports": [], "error": str(e)}

        else:
            args = ["nmap", "-sV", "-Pn", "-F", target]
            if self.runner:
                result = self.runner(args)
            else:
                # Default behavior
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    check=False
                )
            
            # Extract stdout
            raw_output = ""
            if isinstance(result, str):
                raw_output = result
            elif hasattr(result, 'stdout'):
                raw_output = result.stdout
            
            return self._parse_nmap_output(raw_output)

    def _parse_nmap_output(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse raw Nmap text output into a structured dictionary.
        """
        ports_data = []
        current_target = "unknown"

        lines = raw_output.splitlines()
        for line in lines:
            line = line.strip()
            
            # Extract target from "Nmap scan report for <target>"
            if line.startswith("Nmap scan report for"):
                parts = line.split("Nmap scan report for")
                if len(parts) > 1:
                    current_target = parts[1].strip()
                    # Remove IP in parens if present: example.com (1.2.3.4) -> example.com
                    if "(" in current_target and current_target.endswith(")"):
                        current_target = current_target.split("(")[0].strip()

            # Parse port lines: "22/tcp open ssh OpenSSH 8.2" or "80/tcp open http"
            # Regex to match: digits/proto state service [version]
            # Note: State is usually "open", "closed", "filtered". We only care about open usually?
            # Prompt implies we capture open ports.
            
            match = re.match(r"^(\d+)/(\w+)\s+(\w+)\s+(\S+)(?:\s+(.*))?$", line)
            if match:
                port_num = int(match.group(1))
                proto = match.group(2)
                state = match.group(3)
                service = match.group(4)
                version = match.group(5) if match.group(5) else ""

                if state == "open":
                    ports_data.append({
                        "port": port_num,
                        "proto": proto,
                        "service": service,
                        "version": version
                    })
                    
            # Fallback for lines without version (standard -F output)
            # "80/tcp open http"
            # The regex above requires at least 4 groups? No, \S+ matches service. 
            # If version is missing (group 5), ? makes it optional.
            # But "80/tcp open http" -> group 4 is 'http'. group 5 is None.
            
        return {
            "target": current_target,
            "ports": ports_data
        }

    def _parse_python_nmap_result(self, nm: Any, target: str) -> Dict[str, Any]:
        """
        Convert python-nmap object to internal structure.
        """
        ports_data = []
        
        # nm might store by IP or hostname.
        # If target was hostname, python-nmap usually keys by IP if resolved?
        # Or keys by the hostname passed if resolution failed? 
        # Safest is to iterate over all hosts in nm.all_hosts() which should strictly be one if we scanned one.
        
        # However, to be precise, let's just look for the host.
        hosts = nm.all_hosts()
        if not hosts:
             return {"target": target, "ports": []}
             
        # Pick the first host (assuming one target)
        host = hosts[0]
        
        if host not in nm.all_hosts():
             return {"target": target, "ports": []}
             
        # Get protocols
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = nm[host][proto][port]['state']
                if state == 'open':
                    service = nm[host][proto][port].get('name', '')
                    product = nm[host][proto][port].get('product', '')
                    version = nm[host][proto][port].get('version', '')
                    
                    full_version = f"{product} {version}".strip()
                    
                    ports_data.append({
                        "port": port,
                        "proto": proto,
                        "service": service,
                        "version": full_version
                    })
        
        # If target looks like an IP, use it, otherwise try to get hostname from scan?
        # But we return the target string requested or the one found?
        # Prompt example returns "target": "example.com".
        
        return {
            "target": target, # Return requested target name for consistency
            "ports": ports_data
        }
