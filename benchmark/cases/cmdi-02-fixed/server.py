import os
import shlex
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("cmdi-02-fixed")


def _run_grep(pattern: str) -> str:
    os.system(f"grep {shlex.quote(pattern)} /var/log/app.log > /tmp/out.txt")
    with open("/tmp/out.txt") as f:
        return f.read()


@mcp.tool()
def search_logs(pattern: str) -> str:
    """Busca un patrón en el log de la aplicación."""
    return _run_grep(pattern)


if __name__ == "__main__":
    mcp.run()
