import json
from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table

class Formatter:
    def __init__(self):
        self.console = Console()

    def info(self, message: str) -> None:
        """
        Print an informational message using Rich.
        """
        self.console.print(message)

    def format_report_human(self, report: Dict[str, Any]) -> str:
        """
        Format the report as a human-readable string.
        """
        target = report.get("target", "Unknown")
        ports = report.get("ports", [])
        
        lines = []
        lines.append(f"Scan Report for: {target}")
        lines.append("-" * (len(lines[0])))
        lines.append("")
        
        if not ports:
            lines.append("No open ports found or scan failed.")
        else:
            lines.append(f"Open Ports ({len(ports)} found):")
            # Simple text table alignment
            # PORT   PROTO SERVICE VERSION
            header = f"{'PORT':<8} {'PROTO':<6} {'SERVICE':<15} {'VERSION'}"
            lines.append(header)
            
            for port in ports:
                p_str = str(port.get("port", ""))
                proto = port.get("proto", "")
                service = port.get("service", "")
                version = port.get("version", "")
                
                line = f"{p_str:<8} {proto:<6} {service:<15} {version}"
                lines.append(line.rstrip())
        
        fingerprints = report.get("fingerprints", [])
        if fingerprints:
            lines.append("")
            lines.append(f"Detected Components: {', '.join(fingerprints)}")
            
        cves = report.get("cves", [])
        if cves:
            lines.append("")
            lines.append(f"Vulnerabilities ({len(cves)} found):")
            for cve in cves:
                cve_id = cve.get("cve_id", "Unknown")
                summary = cve.get("summary", "No summary")
                cvss = cve.get("cvss", "N/A")
                lines.append(f" - {cve_id} (CVSS: {cvss}): {summary}")
                
        return "\n".join(lines)

    def format_report_json(self, report: Dict[str, Any]) -> str:
        """
        Format the report as a JSON string.
        """
        return json.dumps(report, indent=2)
