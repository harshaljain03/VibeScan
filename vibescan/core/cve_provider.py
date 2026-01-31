from typing import List, Dict, Protocol, Any

class CVEProvider(Protocol):
    def lookup_by_fingerprint(self, fingerprints: List[str]) -> List[Dict[str, Any]]:
        """
        Lookup CVEs for a list of component fingerprints.
        
        :param fingerprints: List of component names (e.g. "ssh", "wordpress").
        :return: List of CVE dictionaries.
        """
        ...

class StubCVEProvider:
    def lookup_by_fingerprint(self, fingerprints: List[str]) -> List[Dict[str, Any]]:
        """
        Return fake CVEs for testing purposes.
        """
        results = []
        for fp in fingerprints:
            if fp == "wordpress":
                results.append({
                    "cve_id": "CVE-2021-9999",
                    "summary": "Fake WordPress vulnerability",
                    "cvss": 9.8,
                    "exploit_exists": True
                })
                results.append({
                    "cve_id": "CVE-2021-8888",
                    "summary": "Another Fake WordPress vulnerability",
                    "cvss": 5.0,
                    "exploit_exists": False
                })
            elif fp == "ssh":
                results.append({
                    "cve_id": "CVE-2020-1234",
                    "summary": "OpenSSH Fake Vuln",
                    "cvss": 7.5,
                    "exploit_exists": False
                })
        return results

def top_n_cves(cves: List[Dict[str, Any]], n: int = 3) -> List[Dict[str, Any]]:
    """
    Filter and sort CVEs to return the top N most critical.
    Sorting criteria: Exploit exists (True first), then CVSS score (descending).
    """
    # Sort key: tuple (exploit_exists desc, cvss desc)
    # Boolean True > False in Python sorts, so exploit_exists works naturally if we want True first?
    # True is 1, False is 0. So True > False.
    # We want desc for both.
    
    sorted_cves = sorted(
        cves,
        key=lambda x: (x.get("exploit_exists", False), x.get("cvss", 0.0)),
        reverse=True
    )
    
    return sorted_cves[:n]
