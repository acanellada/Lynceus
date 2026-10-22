import re
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("cmdi-01-fixed")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


@mcp.tool()
def ping(host: str) -> str:
    """Comprueba si un host responde."""
    if not HOST_RE.fullmatch(host):
        raise ValueError("host inválido")
    result = subprocess.run(
        ["ping", "-c", "1", host], capture_output=True, text=True
    )
    return result.stdout


if __name__ == "__main__":
    mcp.run()
    