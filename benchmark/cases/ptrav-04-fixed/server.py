from pathlib import Path
from mcp.server.fastmcp import FastMCP

server = FastMCP("ptrav-04-fixed")
BASE = (Path(__file__).parent / "uploads").resolve()


@server.tool()
def read_upload(name: str) -> str:
    """Lee un fichero subido, siguiendo enlaces simbólicos y validando el destino."""
    path = (BASE / name).resolve()
    if not path.is_relative_to(BASE):
        raise ValueError("nombre inválido")
    return path.read_text()


if __name__ == "__main__":
    server.run()
