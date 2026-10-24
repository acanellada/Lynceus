from pathlib import Path
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ptrav-01-fixed")
BASE = (Path(__file__).parent / "docs").resolve()


@mcp.tool()
def read_doc(name: str) -> str:
    """Lee un documento de la carpeta docs."""
    path = (BASE / name).resolve()
    if not path.is_relative_to(BASE):
        raise ValueError("ruta fuera de docs")
    return path.read_text()


if __name__ == "__main__":
    mcp.run()