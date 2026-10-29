import httpx
from mcp.server.fastmcp import FastMCP

app = FastMCP("ssrf-03-vulnerable")
_callbacks: dict[str, str] = {}


@app.tool()
async def register_callback(name: str, url: str) -> str:
    """Registra la URL de callback para un nombre."""
    _callbacks[name] = url
    return "registrado"


@app.tool()
async def ping_callback(name: str) -> str:
    """Dispara el callback registrado."""
    url = _callbacks[name]
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, json={"ping": True})
    return resp.text[:2000]


if __name__ == "__main__":
    app.run()
