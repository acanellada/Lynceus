"""Arranca un servidor MCP por stdio dentro del sandbox.

Solo biblioteca estándar y `mcp`: este script se ejecuta dentro del contenedor,
donde no está instalado el paquete `lynceus_sec`.

Dos modos:
- `list` (por defecto): initialize + list_tools, sin llamar a ninguna tool.
- `validate`: recibe una lista de intentos (`--attempts`, JSON) y para cada uno
  arranca un servidor nuevo, llama a la tool indicada y comprueba si el fichero
  canario de ese intento existe. Nunca confía en lo que el servidor reporte:
  el canario se comprueba desde aquí, no desde la respuesta de la tool.
"""

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

_ENV_ERROR_MARKERS = (
    "filenotfounderror",
    "no such file or directory",
    "not found",
    "modulenotfounderror",
)


def _describe(exc: BaseException) -> str:
    """Desenvuelve ExceptionGroup para no perder la causa real (p.ej. import fallido)."""
    if isinstance(exc, BaseExceptionGroup):
        return "; ".join(_describe(sub) for sub in exc.exceptions)
    return f"{type(exc).__name__}: {exc}"


def _result_text(result: Any) -> str:
    parts = [getattr(block, "text", None) for block in getattr(result, "content", []) or []]
    text = " ".join(part for part in parts if part)
    return text or "la tool devolvió un error sin texto"


def _looks_like_environment_error(text: str) -> bool:
    """Heurística por texto, no por tipo de excepción: ver limitación en la documentación."""
    lowered = text.lower()
    return any(marker in lowered for marker in _ENV_ERROR_MARKERS)


def _classify_attempt(
    attempt_id: str,
    canary_exists: bool,
    error_kind: str | None,
    error_text: str | None,
) -> dict[str, Any]:
    """error_kind: None (sin error), "protocol" (timeout/caída/fallo de protocolo) o "tool"."""
    if canary_exists:
        return {"id": attempt_id, "status": "confirmed", "detail": error_text}
    if error_kind == "protocol":
        return {"id": attempt_id, "status": "inconclusive", "detail": error_text}
    if error_kind == "tool":
        if error_text is not None and _looks_like_environment_error(error_text):
            return {"id": attempt_id, "status": "inconclusive", "detail": error_text}
        return {"id": attempt_id, "status": "not_confirmed", "detail": error_text}
    return {"id": attempt_id, "status": "not_confirmed", "detail": None}


async def _list_tools(server_path: str) -> dict[str, Any]:
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


async def _call_once(server_path: str, attempt: dict[str, Any]) -> tuple[bool, str | None]:
    """Arranca un servidor nuevo, hace una única llamada y lo cierra."""
    params = StdioServerParameters(command=sys.executable, args=[server_path])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        result = await session.call_tool(attempt["tool"], attempt["arguments"])
    if result.isError:
        return True, _result_text(result)
    return False, None


async def _run_one_attempt(server_path: str, attempt: dict[str, Any], timeout: float) -> dict[str, Any]:
    protocol_error: str | None = None
    tool_error: str | None = None
    try:
        is_error, text = await asyncio.wait_for(_call_once(server_path, attempt), timeout=timeout)
        if is_error:
            tool_error = text
    except Exception as exc:  # noqa: BLE001 - cualquier fallo se clasifica, nunca se propaga
        protocol_error = _describe(exc)

    canary_exists = Path(attempt["canary_path"]).exists()
    error_kind = "protocol" if protocol_error else ("tool" if tool_error else None)
    return _classify_attempt(attempt["id"], canary_exists, error_kind, protocol_error or tool_error)


async def _validate(
    server_path: str,
    attempts: list[dict[str, Any]],
    call_timeout: float,
    total_timeout: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + total_timeout
    results = []
    for attempt in attempts:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            results.append({"id": attempt["id"], "status": "inconclusive", "detail": "tiempo total agotado"})
            continue
        per_attempt = max(0.5, min(call_timeout, remaining))
        results.append(await _run_one_attempt(server_path, attempt, per_attempt))
    return {"results": results}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("server_path")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--mode", choices=["list", "validate"], default="list")
    parser.add_argument("--attempts", default=None)
    parser.add_argument("--total-timeout", type=float, default=60.0)
    args = parser.parse_args()

    if args.mode == "validate":
        attempts = json.loads(args.attempts)
        payload = asyncio.run(_validate(args.server_path, attempts, args.timeout, args.total_timeout))
        print(json.dumps(payload))
        return 0

    try:
        payload = asyncio.run(asyncio.wait_for(_list_tools(args.server_path), timeout=args.timeout))
    except Exception as exc:  # noqa: BLE001 - el harness reporta cualquier fallo como JSON, no lo propaga
        print(json.dumps({"error": _describe(exc)}))
        return 1

    print(json.dumps(payload))
    return 0


if __name__ == "__main__":
    sys.exit(main())
