from pathlib import Path
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ptrav-01-vulnerable")
BASE = Path(__file__).parent / "docs"


@mcp.tool()
def read_doc(name: str) -> str:
    """Lee un documento de la carpeta docs."""
    return (BASE / name).read_text()


if __name__ == "__main__":
    mcp.run()