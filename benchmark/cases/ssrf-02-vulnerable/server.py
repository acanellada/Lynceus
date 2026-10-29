import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ssrf-02-vulnerable")


def _get(url: str) -> str:
    resp = requests.get(url, timeout=5)
    return resp.text[:5000]


@mcp.tool()
def fetch_webhook(url: str) -> str:
    """Descarga el contenido de una URL de webhook."""
    return _get(url)


if __name__ == "__main__":
    mcp.run()
