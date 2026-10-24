import urllib.request
from urllib.parse import urlparse
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ssrf-01-fixed")
ALLOWED_HOSTS = {"example.com", "docs.example.com"}


@mcp.tool()
def fetch(url: str) -> str:
    """Descarga el contenido de una URL permitida."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("url no permitida")
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.read(100_000).decode("utf-8", "replace")


if __name__ == "__main__":
    mcp.run()