import re
import subprocess
from mcp.server.fastmcp import FastMCP

app = FastMCP("cmdi-03-fixed")
REF_RE = re.compile(r"^(?!-)[A-Za-z0-9._/-]{1,100}$")


@app.tool()
def git_log(ref) -> str:
    """Muestra el último commit de una referencia git."""
    if not REF_RE.fullmatch(ref):
        raise ValueError("referencia inválida")
    result = subprocess.run(
        ["git", "log", "-1", "--end-of-options", ref],
        capture_output=True, text=True, cwd="/repo",
    )
    return result.stdout


if __name__ == "__main__":
    app.run()
