"""Arranca un servidor MCP por stdio dentro del sandbox.

Solo biblioteca estándar y `mcp`: este script se ejecuta dentro del contenedor,
donde no está instalado el paquete `lynceus_sec`.

Dos modos:
- `list` (por defecto): initialize + list_tools, sin llamar a ninguna tool.
- `validate`: recibe una lista de intentos (`--attempts`, JSON) y para cada uno
  arranca un servidor nuevo y llama a la tool indicada. Nunca confía en lo que
  el servidor reporte: el oráculo lo decide el propio harness.
  - Si el intento no lleva `canary_content` (inyección de comandos/argumentos):
    se comprueba si el fichero `canary_path` existe tras la llamada.
  - Si lleva `canary_content` (path traversal): antes de arrancar el servidor
    se escribe `canary_content` en `canary_path`, y se confirma solo si ese
    contenido aparece en el texto de la respuesta (éxito o error).
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


def _content_text(result: Any) -> str:
    """Texto de los bloques de contenido de un CallToolResult, sin fallback."""
    parts = [getattr(block, "text", None) for block in getattr(result, "content", []) or []]
    return " ".join(part for part in parts if part)


def _looks_like_environment_error(text: str, markers: tuple[str, ...] = _ENV_ERROR_MARKERS) -> bool:
    """Heurística por texto, no por tipo de excepción: ver limitación en la documentación."""
    lowered = text.lower()
    return any(marker in lowered for marker in markers)


def _classify_attempt(
    attempt_id: str,
    canary_exists: bool,
    error_kind: str | None,
    error_text: str | None,
    *,
    environment_markers: tuple[str, ...] = _ENV_ERROR_MARKERS,
) -> dict[str, Any]:
    """error_kind: None (sin error), "protocol" (timeout/caída/fallo de protocolo) o "tool".

    `canary_exists` es el nombre histórico del parámetro, pero es genérico:
    significa "el oráculo confirmó la carga" (fichero creado, o contenido de
    canario filtrado en la respuesta, según la clase de vulnerabilidad).
    `environment_markers` permite que cada clase decida qué errores de tool
    cuentan como fallo de entorno (inconclusive) en vez de resultado negativo.
    """
    if canary_exists:
        return {"id": attempt_id, "status": "confirmed", "detail": error_text}
    if error_kind == "protocol":
        return {"id": attempt_id, "status": "inconclusive", "detail": error_text}
    if error_kind == "tool":
        if error_text is not None and _looks_like_environment_error(error_text, environment_markers):
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


async def _call_once(server_path: str, attempt: dict[str, Any]) -> tuple[bool, str]:
    """Si procede, planta el canario de lectura; arranca un servidor nuevo,
    hace una única llamada y lo cierra."""
    canary_content = attempt.get("canary_content")
    if canary_content is not None:
        Path(attempt["canary_path"]).write_text(canary_content)

    params = StdioServerParameters(command=sys.executable, args=[server_path])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        result = await session.call_tool(attempt["tool"], attempt["arguments"])
    return result.isError, _content_text(result)


async def _run_one_attempt(server_path: str, attempt: dict[str, Any], timeout: float) -> dict[str, Any]:
    protocol_error: str | None = None
    tool_error: str | None = None
    response_text = ""
    try:
        is_error, text = await asyncio.wait_for(_call_once(server_path, attempt), timeout=timeout)
        response_text = text
        if is_error:
            tool_error = text or "la tool devolvió un error sin texto"
    except Exception as exc:  # noqa: BLE001 - cualquier fallo se clasifica, nunca se propaga
        protocol_error = _describe(exc)

    canary_content = attempt.get("canary_content")
    if canary_content is not None:
        canary_exists = canary_content in response_text
    else:
        canary_exists = Path(attempt["canary_path"]).exists()

    error_kind = "protocol" if protocol_error else ("tool" if tool_error else None)
    environment_markers = attempt.get("environment_markers", _ENV_ERROR_MARKERS)
    return _classify_attempt(
        attempt["id"], canary_exists, error_kind, protocol_error or tool_error,
        environment_markers=environment_markers,
    )


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
