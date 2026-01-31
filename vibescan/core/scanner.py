from typing import Any, Dict, Optional, Protocol
from vibescan.core.nmap_wrapper import NmapRunner

class FormatterProtocol(Protocol):
    def info(self, message: str) -> None:
        ...

class VibeScanner:
    def __init__(self, nmap_runner: NmapRunner, formatter: Any):
        """
        Initialize the VibeScanner orchestrator.
        
        :param nmap_runner: An instance of NmapRunner.
        :param formatter: An object with an info(message: str) method for narration.
        """
        self.nmap_runner = nmap_runner
        self.formatter = formatter

    def run_scan(self, target: str, ports: Optional[str] = None, dry_run: bool = False) -> Dict[str, Any]:
        """
        Run the full scan logic on the target.
        
        :param target: Target IP or hostname.
        :param ports: Optional ports specification.
        :param dry_run: If True, may skip some heavy operations or pass flags (logic dependent on components).
        :return: Aggregated scan results.
        """
        
        # Step 1: Port Scanning
        self.formatter.info("[1/4] Scanning common ports")
        
        # Note: In a real scenario, we might pass 'ports' and 'dry_run' to scan_common_ports
        # but the current interface of scan_common_ports only accepts target.
        # We assume scan_common_ports logic handles the basic scan.
        port_results = self.nmap_runner.scan_common_ports(target)
        
        # Future Step: Web Probing (Fingerprinting)
        # self.formatter.info("[2/4] Detecting web stack")
        # web_results = self.web_prober.probe(target, port_results)
        
        # Future Step: CVE Lookup
        # self.formatter.info("[3/4] Checking CVEs")
        # cve_results = self.cve_provider.lookup(port_results)
        
        # Future Step: Reporting/Aggregating
        # self.formatter.info("[4/4] Finishing up")
        
        return {
            "target": target,
            "ports": port_results.get("ports", [])
        }
