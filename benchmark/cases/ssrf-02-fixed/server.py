from urllib.parse import urlparse
import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ssrf-02-fixed")
ALLOWED_HOSTS = {"hooks.example.com"}


def _get(url: str) -> str:
    resp = requests.get(url, timeout=5, allow_redirects=False)
    return resp.text[:5000]


@mcp.tool()
def fetch_webhook(url: str) -> str:
    """Descarga el contenido de una URL de webhook permitida."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("url no permitida")
    return _get(url)


if __name__ == "__main__":
    mcp.run()
