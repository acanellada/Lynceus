import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("cmdi-01-vulnerable")


@mcp.tool()
def ping(host: str) -> str:
    """Comprueba si un host responde."""
    result = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True
    )
    return result.stdout


if __name__ == "__main__":
    mcp.run()