from typer.testing import CliRunner
from unittest.mock import patch
from vibescan.cli import app

runner = CliRunner()

def test_doctor_success():
    """Test doctor command when all checks pass."""
    with patch("vibescan.cli.check_python", return_value=(True, "Python OK")), \
         patch("vibescan.cli.check_nmap", return_value=(True, "Nmap OK")), \
         patch("vibescan.cli.check_internet", return_value=(True, "Internet OK")):
        
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "VibeScan Environment Check" in result.stdout
        # Rich output might contain escape codes, but the text should be there.
        assert "Python OK" in result.stdout
        assert "Nmap OK" in result.stdout
        assert "Internet OK" in result.stdout
        assert "All checks passed" in result.stdout

def test_doctor_failure():
    """Test doctor command when some checks fail."""
    with patch("vibescan.cli.check_python", return_value=(True, "Python OK")), \
         patch("vibescan.cli.check_nmap", return_value=(False, "Nmap missing")), \
         patch("vibescan.cli.check_internet", return_value=(False, "No Internet")):
        
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 2
        assert "Python OK" in result.stdout
        assert "Nmap missing" in result.stdout
        assert "No Internet" in result.stdout
        assert "Some checks failed" in result.stdout
