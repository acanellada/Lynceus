import urllib.request
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ssrf-01-vulnerable")


@mcp.tool()
def fetch(url: str) -> str:
    """Descarga el contenido de una URL."""
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.read(100_000).decode("utf-8", "replace")


if __name__ == "__main__":
    mcp.run()