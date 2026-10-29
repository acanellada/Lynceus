import ipaddress
import socket
import httpx
from mcp.server.fastmcp import FastMCP
from urllib.parse import urlparse

app = FastMCP("ssrf-03-fixed")
_callbacks: dict[str, str] = {}

def _is_public(url: str) -> bool:
    host = urlparse(url).hostname
    ip = ipaddress.ip_address(socket.gethostbyname(host))
    return not (ip.is_private or ip.is_loopback or ip.is_link_local)

@app.tool()
async def register_callback(name: str, url: str) -> str:
    """Registra la URL de callback para un nombre, si resuelve a una IP pública."""
    if urlparse(url).scheme != "https" or not _is_public(url):
        raise ValueError("url no permitida")
    _callbacks[name] = url
    return "registrado"
@app.tool()
async def ping_callback(name: str) -> str:
    """Dispara el callback registrado."""
    url = _callbacks[name]
    async with httpx.AsyncClient(follow_redirects=False) as client:
        resp = await client.post(url, json={"ping": True})
    return resp.text[:2000]
if __name__ == "__main__":
    app.run()
