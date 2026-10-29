from mcp.server.fastmcp import FastMCP

app = FastMCP("ptrav-03-fixed")
BASE_DIR = "/srv/reports"
ALLOWED_FILENAMES = {"summary.txt", "incidents.txt", "audit.txt"}


@app.tool()
async def read_report(filename: str) -> str:
    """Lee un informe permitido de /srv/reports."""
    if filename not in ALLOWED_FILENAMES:
        raise ValueError("informe no permitido")
    path = BASE_DIR + "/" + filename
    with open(path) as f:
        return f.read()


if __name__ == "__main__":
    app.run()
