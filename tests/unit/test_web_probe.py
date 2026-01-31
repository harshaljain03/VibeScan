import httpx
from unittest.mock import MagicMock, patch
from vibescan.core.web_probe import probe_http

def test_probe_http_success():
    """Test probe_http with a successful response."""
    html_content = """
    <html>
        <head>
            <title>Example Domain</title>
            <meta name="generator" content="WordPress 5.8">
        </head>
        <body></body>
    </html>
    """
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = html_content
    mock_response.headers = {"server": "nginx"}
    
    with patch("httpx.get", return_value=mock_response) as mock_get:
        result = probe_http("https://example.com")
        
        mock_get.assert_called_with("https://example.com", timeout=5.0, follow_redirects=True)
        
        assert result["url"] == "https://example.com"
        assert result["status_code"] == 200
        assert result["title"] == "Example Domain"
        assert result["meta_generator"] == "WordPress 5.8"
        assert result["headers"]["server"] == "nginx"

def test_probe_http_failure():
    """Test probe_http with a request error."""
    with patch("httpx.get", side_effect=httpx.RequestError("Connection failed")):
        result = probe_http("https://example.com")
        
        assert result["status_code"] == 0
        assert "Connection failed" in result["error"]

def test_probe_http_no_meta():
    """Test probe_http with no title or generator."""
    html_content = "<html><body><h1>Hi</h1></body></html>"
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = html_content
    mock_response.headers = {}
    
    with patch("httpx.get", return_value=mock_response):
        result = probe_http("https://example.com")
        
        assert result["title"] is None
        assert result["meta_generator"] is None
