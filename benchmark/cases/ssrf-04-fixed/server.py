import ipaddress
import socket
import urllib.request
from urllib.parse import urlparse
from mcp.server.fastmcp import FastMCP

server = FastMCP("ssrf-04-fixed")

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

_opener = urllib.request.build_opener(_NoRedirect)

def _is_public(host: str) -> bool:
    ip = ipaddress.ip_address(socket.gethostbyname(host))
    return not (ip.is_private or ip.is_loopback or ip.is_link_local)

@server.tool()
def proxy_request(target: str) -> str:
    """Reenvía una petición GET a una URL http(s) con host público."""
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not _is_public(parsed.hostname):
        raise ValueError("url no permitida")
    with _opener.open(target, timeout=5) as r:
        return r.read(50_000).decode("utf-8", "replace")

if __name__ == "__main__":
    server.run()
