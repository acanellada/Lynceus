import os
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ptrav-02-fixed")
BASE = os.path.realpath(os.path.join(os.path.dirname(__file__), "assets"))


def _load_asset(path) -> str:
    full = os.path.realpath(os.path.join(BASE, path))
    if os.path.commonpath([BASE, full]) != BASE:
        raise ValueError("ruta fuera de assets")
    with open(full) as f:
        return f.read()


@mcp.tool()
def get_asset(path) -> str:
    """Devuelve el contenido de un asset permitido."""
    return _load_asset(path)


if __name__ == "__main__":
    mcp.run()
