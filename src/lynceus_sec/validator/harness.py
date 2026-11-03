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
    se escribe `canary_content` en `canary_path` (creando el directorio padre
    si falta), y se confirma solo si ese contenido aparece en el texto de la
    respuesta (éxito o error). Si además lleva `symlink_path`/`symlink_target`,
    se crea ese enlace simbólico antes de la llamada. Antes de arrancar
    cualquier servidor también se crea `$HOME` si no existe. Toda ruta que se
    vaya a crear (directorio, canario o enlace, y el destino del enlace) se
    normaliza y se comprueba que cae bajo /tmp; si no, se rechaza sin crear
    nada: defensa en profundidad, ya que el host nunca debería construir un
    intento con una ruta fuera de /tmp, pero el harness no confía en ello.
  - Si lleva `calls` (SSRF, intentos en dos pasos): en vez de una única
    llamada a `tool`/`arguments`, ejecuta la lista de llamadas en orden
    dentro de la misma sesión del mismo servidor, y agrega el resultado
    (cualquier llamada con error marca el intento como erróneo; los textos
    de todas las respuestas se concatenan). La confirmación por token del
    receptor no la decide este harness: vive fuera, en ssrf.py.

El punto de entrada (`server_path`, ya resuelto por el llamador a `/case/<entry>`)
y el `PYTHONPATH` del servidor analizado (reenviado desde `os.environ`, ver
`_server_env`) son los dos únicos ejes configurables; el resto de protecciones
del sandbox no cambia.
"""

import argparse
import asyncio
import json
import os
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

_DEFAULT_HOME = "/tmp/lynceus-root"
_ALLOWED_ROOT = "/tmp"


def _ensure_under_tmp(path: str, *, what: str) -> Path:
    """Normaliza `path` (sin tocar disco) y comprueba que cae bajo /tmp.

    Defensa en profundidad: el host (payloads.py) nunca debería construir un
    intento con una ruta fuera de /tmp, pero el harness no se fía de eso
    antes de crear ningún directorio, fichero de canario o enlace simbólico.
    Lanza ValueError sin crear nada si la ruta normalizada queda fuera.
    """
    normalized = Path(os.path.normpath(path))
    if not str(normalized).startswith(_ALLOWED_ROOT + "/"):
        raise ValueError(f"{what} fuera de {_ALLOWED_ROOT}, rechazado: {path!r}")
    return normalized


def _prepare_home() -> None:
    """Crea $HOME (o el valor por defecto) si no existe, antes de arrancar cualquier servidor."""
    home = _ensure_under_tmp(os.environ.get("HOME", _DEFAULT_HOME), what="HOME")
    home.mkdir(parents=True, exist_ok=True)


def _server_env() -> dict[str, str] | None:
    """`stdio_client` no hereda el entorno completo del harness por seguridad
    (solo una lista fija de variables vía `get_default_environment()`, entre
    ellas `HOME`); lo que se pase aquí se combina con esas por encima, nunca
    las sustituye (`get_default_environment() | (server.env or {})` en el
    SDK). Por eso basta con reenviar `PYTHONPATH` si está fijado: `HOME` y el
    resto de variables por defecto llegan igual al servidor analizado."""
    pythonpath = os.environ.get("PYTHONPATH")
    return {"PYTHONPATH": pythonpath} if pythonpath else None


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
    params = StdioServerParameters(command=sys.executable, args=[server_path], env=_server_env())
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
    """Si procede, planta el canario de lectura y el enlace simbólico; arranca
    un servidor nuevo y ejecuta una única llamada (`tool`/`arguments`) o, si
    el intento lleva `calls`, la secuencia completa en la misma sesión, y lo
    cierra."""
    canary_content = attempt.get("canary_content")
    if canary_content is not None:
        canary_path = _ensure_under_tmp(attempt["canary_path"], what="canary_path")
        canary_path.parent.mkdir(parents=True, exist_ok=True)
        canary_path.write_text(canary_content)

    symlink_path = attempt.get("symlink_path")
    symlink_target = attempt.get("symlink_target")
    if symlink_path is not None and symlink_target is not None:
        link_path = _ensure_under_tmp(symlink_path, what="symlink_path")
        link_target = _ensure_under_tmp(symlink_target, what="symlink_target")
        link_path.parent.mkdir(parents=True, exist_ok=True)
        if not link_path.is_symlink():
            link_path.symlink_to(link_target)

    params = StdioServerParameters(command=sys.executable, args=[server_path], env=_server_env())
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        calls = attempt.get("calls")
        if calls is None:
            result = await session.call_tool(attempt["tool"], attempt["arguments"])
            return result.isError, _content_text(result)

        is_error = False
        texts: list[str] = []
        for call in calls:
            result = await session.call_tool(call["tool"], call["arguments"])
            is_error = is_error or result.isError
            text = _content_text(result)
            if text:
                texts.append(text)
        return is_error, " ".join(texts)


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
    canary_path = attempt.get("canary_path")
    if canary_content is not None:
        canary_exists = canary_content in response_text
    elif canary_path is not None:
        canary_exists = Path(canary_path).exists()
    else:
        # Sin canario propio (p.ej. las cargas de URL de SSRF): el harness no
        # puede confirmar nada por sí mismo, la confirmación por token vive
        # fuera, en ssrf.py, tras leer el registro del receptor.
        canary_exists = False

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

    try:
        _prepare_home()
    except Exception as exc:  # noqa: BLE001 - igual que el resto: se reporta como JSON, nunca se propaga
        print(json.dumps({"error": _describe(exc)}))
        return 1

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
