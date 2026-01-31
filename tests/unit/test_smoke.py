from typer.testing import CliRunner
from unittest.mock import patch
from vibescan.cli import app
import vibescan

runner = CliRunner()

def test_app_exists():
    """Verify that the app object exists and is a Typer instance."""
    assert app is not None

def test_version():
    """Verify that the version flag works."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "VibeScan v0.1.0" in result.stdout

def test_scan_help():
    """Verify that the scan command help works."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "Scan a target for vulnerabilities." in result.stdout

def test_scan_smoke():
    """Verify that the scan command runs with dry-run."""
    with patch("vibescan.cli.NmapRunner") as MockRunner:
        MockRunner.return_value.scan_common_ports.return_value = {"ports": []}
        result = runner.invoke(app, ["scan", "localhost", "--dry-run"])
        assert result.exit_code == 0
        assert "Scan Report for: localhost" in result.stdout
