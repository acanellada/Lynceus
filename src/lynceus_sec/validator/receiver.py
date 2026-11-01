"""Receptor de canarios SSRF: solo biblioteca estándar.

Escucha HTTP en el puerto 8080 dentro de la red interna y escribe una línea
JSON por petición (method, path, host) a stdout con flush inmediato. No
decide nada sobre el resultado: el oráculo que busca el token en estas
líneas vive en ssrf.py, fuera del servidor analizado, nunca aquí.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class _CanaryHandler(BaseHTTPRequestHandler):
    def _handle(self) -> None:
        entry = {
            "method": self.command,
            "path": self.path,
            "host": self.headers.get("Host", ""),
        }
        print(json.dumps(entry), flush=True)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_HEAD = _handle
    do_PATCH = _handle
    do_OPTIONS = _handle

    def log_message(self, format: str, *args: object) -> None:
        pass  # la única salida es la línea JSON de _handle, no el log por defecto a stderr


def main() -> int:
    server = HTTPServer(("0.0.0.0", 8080), _CanaryHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
