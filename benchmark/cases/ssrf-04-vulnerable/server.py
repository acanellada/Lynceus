import urllib.request
from mcp.server.fastmcp import FastMCP

server = FastMCP("ssrf-04-vulnerable")


@server.tool()
def proxy_request(target: str) -> str:
    """Reenvía una petición GET a la URL indicada."""
    with urllib.request.urlopen(target, timeout=5) as r:
        return r.read(50_000).decode("utf-8", "replace")


if __name__ == "__main__":
    server.run()
