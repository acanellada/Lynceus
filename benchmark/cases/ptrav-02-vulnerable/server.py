import os
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ptrav-02-vulnerable")
BASE = os.path.join(os.path.dirname(__file__), "assets")


def _load_asset(path) -> str:
    full = os.path.join(BASE, path)
    with open(full) as f:
        return f.read()


@mcp.tool()
def get_asset(path) -> str:
    """Devuelve el contenido de un asset."""
    return _load_asset(path)


if __name__ == "__main__":
    mcp.run()
