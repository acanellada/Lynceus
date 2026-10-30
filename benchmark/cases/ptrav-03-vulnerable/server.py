from mcp.server.fastmcp import FastMCP

app = FastMCP("ptrav-03-vulnerable")
BASE_DIR = __file__.rsplit("/", 1)[0] + "/reports"


@app.tool()
async def read_report(filename: str) -> str:
    """Lee un informe de /srv/reports."""
    path = BASE_DIR + "/" + filename
    with open(path) as f:
        return f.read()


if __name__ == "__main__":
    app.run()
