import sys
import pytest
from unittest.mock import MagicMock, patch
from vibescan.utils.env_checks import check_python, check_nmap, check_internet

def test_check_python_success():
    """Test check_python with a valid version."""
    with patch.object(sys, 'version_info') as mock_version:
        mock_version.major = 3
        mock_version.minor = 10
        ok, msg = check_python(min_major=3, min_minor=10)
        assert ok is True
        assert "supported" in msg

def test_check_python_failure():
    """Test check_python with an invalid version."""
    with patch.object(sys, 'version_info') as mock_version:
        mock_version.major = 3
        mock_version.minor = 9
        ok, msg = check_python(min_major=3, min_minor=10)
        assert ok is False
        assert "is required" in msg

def test_check_nmap_found_shutil():
    """Test check_nmap when nmap is found via shutil.which."""
    with patch("shutil.which", return_value="/usr/bin/nmap"):
        ok, msg = check_nmap()
        assert ok is True
        assert "/usr/bin/nmap" in msg

def test_check_nmap_found_import():
    """Test check_nmap when nmap is found via import (shutil.which fails)."""
    with patch("shutil.which", return_value=None), \
         patch.dict(sys.modules, {'nmap': MagicMock()}):
        ok, msg = check_nmap()
        assert ok is True
        assert "module is installed" in msg

def test_check_nmap_not_found():
    """Test check_nmap when nmap is neither in path nor importable."""
    with patch("shutil.which", return_value=None), \
         patch.dict(sys.modules):
        # Ensure nmap is not in modules
        if 'nmap' in sys.modules:
            del sys.modules['nmap']
        
        # We need to ensure import nmap raises ImportError.
        # However, since we are patching sys.modules, built-in import should fail if not found.
        # But to be safe let's use side_effect on builtins.__import__ is risky.
        # Easier: The real environment might have python-nmap installed (from our pip install).
        # We must mask it.
        # But actually, `patch.dict(sys.modules)` only modifies the dict for the scope.
        # Standard import mechanism checks sys.modules. 
        # If we want to simulate ImportError when it IS installed, we have to do more.
        # But wait, `check_nmap` does `try: import nmap`.
        # If we patch `sys.modules` and remove `nmap`, the import system will try to find it.
        # If it's really installed, it will resolve.
        # So we need to mock `builtins.__import__` or ensure it fails.
        # A simpler way is to patch `check_nmap`'s internal import? No, can't easily do that.
        
        # Approach: Use `sys.modules` to inject a None or raise error?
        # Actually, best way to mock failed import of an installed module is confusing.
        # Let's try `patch.dict(sys.modules, {'nmap': None})`. Python < 3.3 treated this as "not found" relative import, but here?
        # Let's just assume for now we can rely on `shutil.which` mostly.
        # If `python-nmap` IS installed (it is), `import nmap` succeeds.
        # So to test FAILURE, we must verify that implementation handles ImportError.
        # We can use `with patch('builtins.__import__', side_effect=ImportError)` but that breaks everything.
        pass

    # Better approach for testing failure when module exists:
    # Wrap the import in a helper or just accept that we can't easily test the ImportError branch 
    # if the package is installed, UNLESS we use a specialized mock.
    # Let's try to mock the specific import?
    # No, let's just use `unittest.mock.patch.dict(sys.modules)` with a key that causes failure?
    # No, removing it just makes it search path.
    
    # Actually, we can use `sys.modules['nmap'] = None` maybe?
    # No, that might imply "module not found" in some python versions but maybe not 3.10+.
    pass

# Redefine the failing test with a robust strategy
def test_check_nmap_not_found_robust():
    """Test check_nmap failure."""
    # We simulate shutil.which returning None
    with patch("shutil.which", return_value=None):
        # And we need `import nmap` to fail.
        # Since we know `check_nmap` does `import nmap`, we can patch `builtins.__import__` 
        # CAREFULLY. Or simpler:
        # Check if we can just patch the function's logic? No, black box preference.
        
        # Let's try `sys.modules` manipulation.
        # If we set `sys.modules['nmap']` to a Mock that raises ImportError on access? No.
        
        # Let's just create a context where we hide the module.
        with patch.dict(sys.modules):
            if 'nmap' in sys.modules:
                del sys.modules['nmap']
            # And we need to make sure the loader doesn't find it.
            # This is hard if it's in site-packages.
            
            # Alternative: Assume it MIGHT pass if nmap is installed, but we want to verify the logic.
            # Let's look at the code:
            # try: import nmap
            # except ImportError: ...
            
            # If we simply define a custom find_spec or something? 
            # Too complex.
            
            # What if we patch the function `check_nmap`? No.
            
            # Let's use the `mask_modules` pattern if possible?
            pass

    # Let's try a simpler mock for the `import nmap` line by not mocking it directly but 
    # acknowledging that if `python-nmap` is installed, this test requires un-installing it conceptually.
    # But wait, the user asked for "All external calls must be mockable".
    # Import is technically external?
    
    # Let's just mock `builtins.__import__` but only fail for 'nmap'.
    import builtins
    orig_import = builtins.__import__
    
    def side_effect(name, *args, **kwargs):
        if name == 'nmap':
            raise ImportError("No module named 'nmap'")
        return orig_import(name, *args, **kwargs)
        
    with patch("shutil.which", return_value=None), \
         patch("builtins.__import__", side_effect=side_effect):
        ok, msg = check_nmap()
        assert ok is False
        assert "not found" in msg

def test_check_internet_success():
    """Test check_internet with successful connection."""
    with patch("socket.create_connection") as mock_socket:
        ok, msg = check_internet()
        assert ok is True
        assert "Successfully connected" in msg
        mock_socket.assert_called_once()

def test_check_internet_failure():
    """Test check_internet with connection error."""
    with patch("socket.create_connection", side_effect=OSError("Unreachable")):
        ok, msg = check_internet()
        assert ok is False
        assert "Internet check failed" in msg
