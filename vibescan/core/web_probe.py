import httpx
from bs4 import BeautifulSoup
from typing import Dict, Any, Optional

def probe_http(url: str, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Probe a HTTP URL to extract metadata.
    
    :param url: The URL to probe (e.g., https://example.com).
    :param timeout: Request timeout in seconds.
    :return: Dictionary containing status code, title, meta generator, and headers.
    """
    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        title = None
        if soup.title and soup.title.string:
            title = soup.title.string.strip()
            
        meta_generator = None
        generator_tag = soup.find("meta", attrs={"name": "generator"})
        if generator_tag and generator_tag.get("content"):
            meta_generator = generator_tag["content"]
            
        return {
            "url": url,
            "status_code": response.status_code,
            "title": title,
            "meta_generator": meta_generator,
            "headers": dict(response.headers)
        }
    except httpx.RequestError as e:
        # Return partial info or re-raise? 
        # For this task, let's assume we return a dict indicating failure or just re-raise.
        # But to match the return signature and typically graceful degradation in scanners:
        return {
            "url": url,
            "status_code": 0,
            "error": str(e),
            "title": None,
            "meta_generator": None,
            "headers": {}
        }
