"""Arranca un servidor MCP por stdio dentro del sandbox y lista sus herramientas.

Solo biblioteca estándar y `mcp`: este script se ejecuta dentro del contenedor,
donde no está instalado el paquete `lynceus_sec`. Nunca llama a una herramienta,
solo hace `initialize` + `list_tools`.
"""

import argparse
import asyncio
import json
import sys

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def _list_tools(server_path: str) -> dict:
    params = StdioServerParameters(command=sys.executable, args=[server_path])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        result = await session.list_tools()
    return {
        "tools": [
            {"name": tool.name, "input_schema": tool.inputSchema}
            for tool in result.tools
        ]
    }


def _describe(exc: BaseException) -> str:
    """Desenvuelve ExceptionGroup para no perder la causa real (p.ej. import fallido)."""
    if isinstance(exc, BaseExceptionGroup):
        return "; ".join(_describe(sub) for sub in exc.exceptions)
    return f"{type(exc).__name__}: {exc}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("server_path")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    try:
        payload = asyncio.run(asyncio.wait_for(_list_tools(args.server_path), timeout=args.timeout))
    except Exception as exc:  # noqa: BLE001 - el harness reporta cualquier fallo como JSON, no lo propaga
        print(json.dumps({"error": _describe(exc)}))
        return 1

    print(json.dumps(payload))
    return 0


if __name__ == "__main__":
    sys.exit(main())
