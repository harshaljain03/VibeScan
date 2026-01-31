import sys
import shutil
import socket
from typing import Tuple

def check_python(min_major: int = 3, min_minor: int = 10) -> Tuple[bool, str]:
    """
    Check if the current Python version meets the minimum requirements.
    """
    current_version = sys.version_info
    if current_version.major < min_major or (current_version.major == min_major and current_version.minor < min_minor):
        return False, f"Python {min_major}.{min_minor}+ is required, but found {current_version.major}.{current_version.minor}."
    return True, f"Python version {current_version.major}.{current_version.minor} is supported."

def check_nmap() -> Tuple[bool, str]:
    """
    Check if nmap is available in the system path or via python-nmap.
    """
    # First check if the binary is in the PATH
    nmap_path = shutil.which("nmap")
    if nmap_path:
        return True, f"Nmap found at {nmap_path}."
    
    # Alternatively try to import python-nmap (though it usually relies on the binary)
    try:
        import nmap
        # This just checks if the library is installed, not if nmap binary is there necessarily,
        # but the prompt asked to "try to import nmap (python-nmap) OR use shutil.which".
        # Usually python-nmap fails at runtime if nmap is missing, but let's follow instructions.
        return True, "Nmap module is installed."
    except ImportError:
        pass

    return False, "Nmap binary not found in PATH."

def check_internet(host: str = "8.8.8.8", port: int = 53, timeout: float = 2.0) -> Tuple[bool, str]:
    """
    Check internet connectivity by attempting to connect to a host.
    """
    try:
        # We use socket.create_connection which handles DNS resolution if needed,
        # but 8.8.8.8 avoids DNS.
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"Successfully connected to {host}:{port}."
    except OSError as e:
        return False, f"Internet check failed: {e}"
