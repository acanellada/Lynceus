from pathlib import Path
from mcp.server.fastmcp import FastMCP

server = FastMCP("ptrav-04-vulnerable")
BASE = Path(__file__).parent / "uploads"


@server.tool()
def read_upload(name: str) -> str:
    """Lee un fichero subido por el usuario."""
    if ".." in name:
        raise ValueError("nombre inválido")
    path = BASE / name
    return path.read_text()


if __name__ == "__main__":
    server.run()
