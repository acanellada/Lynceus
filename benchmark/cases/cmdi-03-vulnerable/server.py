import subprocess
from mcp.server.fastmcp import FastMCP

app = FastMCP("cmdi-03-vulnerable")


@app.tool()
def git_log(ref) -> str:
    """Muestra el último commit de una referencia git."""
    result = subprocess.run(
        ["git", "log", "-1", ref], capture_output=True, text=True, cwd="/repo"
    )
    return result.stdout


if __name__ == "__main__":
    app.run()
