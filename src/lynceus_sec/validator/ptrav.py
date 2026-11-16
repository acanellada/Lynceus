"""Genera y ejecuta intentos de path traversal sobre un caso.

Misma estructura que cmdi.py. Todo se deduce de `list_tools` dentro del
sandbox: ningún parámetro, nombre de tool ni ruta es específico de un caso
concreto.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from lynceus_sec.core.model import Finding, ReproductionCall, VulnClass
from lynceus_sec.validator.payloads import (
    build_path_traversal_payloads,
    build_path_traversal_write_payloads,
    build_positive_control_payload,
    build_positive_control_write_payload,
)
from lynceus_sec.validator.runner import (
    DEFAULT_ENTRY,
    DEFAULT_FS_ROOT,
    DEFAULT_IMAGE,
    kill_container,
    run_harness,
    run_validate,
    run_validate_split,
)

if TYPE_CHECKING:
    from lynceus_sec.validator.parallel import ParallelContext

_NEUTRAL_BY_TYPE: dict[str, Any] = {
    "string": "lynceus",
    "integer": 0,
    "number": 0.0,
    "boolean": False,
    "array": [],
    "object": {},
}

# Valor neutro para un parámetro de texto que, en un intento de escritura,
# no es ni la ruta ni el candidato a contenido elegido para llevar el token
# (p.ej. `encoding` cuando el candidato a contenido es `content`). "lynceus"
# (el valor neutro genérico de arriba) sirve para un texto cualquiera, pero
# no para un parámetro con un conjunto de valores esperado como `encoding`,
# `mode` o `mimetype`: un servidor real puede rechazar o fallar con un valor
# inventado, y eso bastaría para que todas las técnicas salgan
# `not_confirmed` aunque sea vulnerable (bug visto en filesystem-mcp-server
# v1.0.0, donde `encoding` recibía el token). "utf-8" es una codificación
# real, universalmente aceptada, y un valor razonable también para un
# parámetro de texto sin ninguna estructura esperada.
_NEUTRAL_WRITE_TEXT_DEFAULT = "utf-8"

# FileNotFoundError / "No such file or directory" son respuestas normales al
# probar path traversal (la ruta probada puede simplemente no existir); solo
# ModuleNotFoundError indica un problema de entorno ajeno a esta clase.
_ENVIRONMENT_MARKERS = ("modulenotfounderror",)


def _neutral_value(schema: dict[str, Any]) -> Any:
    return _NEUTRAL_BY_TYPE.get(schema.get("type"), "lynceus")


def _string_params(tool: dict[str, Any]) -> list[str]:
    properties = tool.get("input_schema", {}).get("properties", {})
    return [name for name, schema in properties.items() if schema.get("type") == "string"]


def _base_arguments(tool: dict[str, Any], *, skip: str) -> dict[str, Any]:
    """Valores neutros para los parámetros obligatorios distintos de `skip`."""
    schema = tool.get("input_schema", {})
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    return {
        name: _neutral_value(properties[name])
        for name in required
        if name != skip and name in properties
    }


def _write_arguments(
    tool: dict[str, Any], *, path_param: str, content_param: str, path_value: Any, token: str,
) -> dict[str, Any]:
    """Argumentos de un intento de escritura: `path_param` recibe
    `path_value` (la ruta objetivo o la del control positivo);
    `content_param` — el candidato a "esto es el contenido" que se está
    probando en esta variante, ver `build_write_attempts` — recibe el
    token. Cualquier OTRO parámetro de texto recibe
    `_NEUTRAL_WRITE_TEXT_DEFAULT`, nunca el token: ponerle el token a un
    parámetro como `encoding` puede hacer que la llamada falle por un
    valor inventado y enmascare una escritura real. Los no-texto
    obligatorios reciben un valor neutro por tipo, igual que en lectura."""
    schema = tool.get("input_schema", {})
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    arguments: dict[str, Any] = {}
    for name, prop in properties.items():
        if name == path_param:
            continue
        if name == content_param:
            arguments[name] = token
        elif prop.get("type") == "string":
            arguments[name] = _NEUTRAL_WRITE_TEXT_DEFAULT
        elif name in required:
            arguments[name] = _neutral_value(prop)
    arguments[path_param] = path_value
    return arguments


def build_attempts(tools: list[dict[str, Any]], fs_root: str = DEFAULT_FS_ROOT) -> list[dict[str, Any]]:
    """Un intento por cada (parámetro de tipo string, carga) de cada tool, más
    un intento de control positivo informativo por cada (tool, parámetro):
    ver `kind` en cada intento ("traversal" o "positive_control")."""
    attempts: list[dict[str, Any]] = []
    for tool in tools:
        for param in _string_params(tool):
            for payload in build_path_traversal_payloads(fs_root):
                arguments = _base_arguments(tool, skip=param)
                arguments[param] = payload.value
                attempts.append(
                    {
                        "id": uuid.uuid4().hex,
                        "kind": "traversal",
                        "tool": tool["name"],
                        "parameter": param,
                        "technique": payload.technique,
                        "payload": payload.value,
                        "canary_path": payload.canary_path,
                        "canary_content": payload.canary_content,
                        "environment_markers": _ENVIRONMENT_MARKERS,
                        "arguments": arguments,
                        "symlink_path": payload.symlink_path,
                        "symlink_target": payload.symlink_target,
                    }
                )

            control = build_positive_control_payload(fs_root)
            control_arguments = _base_arguments(tool, skip=param)
            control_arguments[param] = control.value
            attempts.append(
                {
                    "id": uuid.uuid4().hex,
                    "kind": "positive_control",
                    "tool": tool["name"],
                    "parameter": param,
                    "technique": "positive_control",
                    "payload": control.value,
                    "canary_path": control.canary_path,
                    "canary_content": control.canary_content,
                    "environment_markers": _ENVIRONMENT_MARKERS,
                    "arguments": control_arguments,
                }
            )
    return attempts


def build_write_attempts(tools: list[dict[str, Any]], fs_root: str = DEFAULT_FS_ROOT) -> list[dict[str, Any]]:
    """Oráculo de escritura. Por cada tool, cada parámetro de texto se prueba
    como ruta (`path_param`, en las tres formas de `build_attempts`); como
    no se sabe cuál de los demás parámetros de texto lleva el contenido, se
    prueba cada uno de ellos por turnos como portador del token
    (`content_param`) — nunca todos a la vez: el resto de parámetros de
    texto recibe `_NEUTRAL_WRITE_TEXT_DEFAULT`, no el token (ver
    `_write_arguments`). Más un intento de control positivo informativo por
    cada combinación (`path_param`, `content_param`), con una ruta objetivo
    dentro del límite. A diferencia de `build_attempts`, el harness nunca
    planta nada en la ruta objetivo: solo se confirma si el propio servidor
    la crea.

    Con S parámetros de texto por tool, hay S*(S-1) combinaciones
    (path_param, content_param); con las 6 técnicas de cada una, son
    S*(S-1)*6 intentos `write` más S*(S-1) controles. Con S=2 (el caso
    común, p.ej. `write_file_tool(path, content)`) son 12+2=14, igual que
    antes de este cambio: solo hay un candidato a contenido posible, así
    que no hay nada que probar por turnos. Con S=3 (p.ej. `path`,
    `content`, `encoding`) son 36+6=42. Si un parámetro de texto es el
    único de la tool (S=1), no se genera ningún intento de escritura para
    él: sin otro parámetro de texto no hay dónde poner el token, y sin
    token `_confirm_write` nunca podría confirmar nada.
    """
    attempts: list[dict[str, Any]] = []
    for tool in tools:
        string_params = _string_params(tool)
        for path_param in string_params:
            content_candidates = [p for p in string_params if p != path_param]
            for content_param in content_candidates:
                for payload in build_path_traversal_write_payloads(fs_root):
                    arguments = _write_arguments(
                        tool, path_param=path_param, content_param=content_param,
                        path_value=payload.value, token=payload.token,
                    )
                    attempts.append(
                        {
                            "id": uuid.uuid4().hex,
                            "kind": "write",
                            "tool": tool["name"],
                            "parameter": path_param,
                            "content_parameter": content_param,
                            "technique": payload.technique,
                            "payload": payload.value,
                            "write_target_path": payload.target_path,
                            "write_token": payload.token,
                            "environment_markers": _ENVIRONMENT_MARKERS,
                            "arguments": arguments,
                            "symlink_path": payload.symlink_path,
                            "symlink_target": payload.symlink_target,
                        }
                    )

                control = build_positive_control_write_payload(fs_root)
                control_arguments = _write_arguments(
                    tool, path_param=path_param, content_param=content_param,
                    path_value=control.value, token=control.token,
                )
                attempts.append(
                    {
                        "id": uuid.uuid4().hex,
                        "kind": "write_positive_control",
                        "tool": tool["name"],
                        "parameter": path_param,
                        "content_parameter": content_param,
                        "technique": "positive_control_write",
                        "payload": control.value,
                        "write_target_path": control.target_path,
                        "write_token": control.token,
                        "environment_markers": _ENVIRONMENT_MARKERS,
                        "arguments": control_arguments,
                    }
                )
    return attempts


def attempts_to_findings(
    case_id: str,
    attempts: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> tuple[list[Finding], list[dict[str, Any]], list[dict[str, Any]]]:
    """Solo los intentos `confirmed` de tipo `traversal` (lectura) o `write`
    (escritura) producen Findings; los `inconclusive` se devuelven aparte.
    Los intentos `positive_control`/`write_positive_control` nunca producen
    Finding ni cuentan como inconclusos: se devuelven en una tercera lista,
    con su resultado tal cual, puramente informativa. El `message` de cada
    Finding indica si la confirmación fue de lectura o de escritura."""
    results_by_id = {result["id"]: result for result in results}
    findings: list[Finding] = []
    inconclusive: list[dict[str, Any]] = []
    positive_controls: list[dict[str, Any]] = []

    for attempt in attempts:
        kind = attempt.get("kind", "traversal")
        result = results_by_id.get(attempt["id"])

        if kind in ("positive_control", "write_positive_control"):
            if result is None:
                positive_controls.append(
                    {**attempt, "status": "inconclusive", "detail": "sin resultado del harness"}
                )
            else:
                positive_controls.append({**attempt, **result})
            continue

        if result is None:
            inconclusive.append({**attempt, "status": "inconclusive", "detail": "sin resultado del harness"})
            continue

        status = result["status"]
        if status == "confirmed":
            if kind == "write":
                evidence = (
                    f"Token propio encontrado en la ruta objetivo fuera del límite: "
                    f"{attempt['write_target_path']!r}"
                )
                direction = "escritura"
            else:
                evidence = f"Contenido del canario leído en la respuesta: {attempt['canary_content']!r}"
                direction = "lectura"
            findings.append(
                Finding(
                    case=case_id,
                    rule_id=f"ptrav-{attempt['technique']}",
                    vuln_class=VulnClass.PATH_TRAVERSAL,
                    tool=attempt["tool"],
                    severity="high",
                    message=(
                        f"Path traversal ({direction}) confirmado en el parámetro "
                        f"{attempt['parameter']!r} de la tool {attempt['tool']!r} "
                        f"({attempt['technique']})"
                    ),
                    evidence=evidence,
                    validated=True,
                    parameter=attempt["parameter"],
                    technique=attempt["technique"],
                    payload=attempt["payload"],
                    reproduction=[ReproductionCall(tool=attempt["tool"], arguments=attempt["arguments"])],
                )
            )
        elif status == "inconclusive":
            inconclusive.append({**attempt, **result})
        # not_confirmed: resultado negativo normal, ni Finding ni informe aparte

    return findings, inconclusive, positive_controls


def validate_case(
    case_dir: Path,
    *,
    image: str = DEFAULT_IMAGE,
    discover_timeout: float = 20.0,
    call_timeout: float = 15.0,
    fs_root: str = DEFAULT_FS_ROOT,
    entry: str = DEFAULT_ENTRY,
    pythonpath: list[str] | None = None,
    server_python: str | None = None,
    jobs: int = 1,
    ctx: ParallelContext | None = None,
) -> tuple[list[Finding], list[dict[str, Any]], list[dict[str, Any]]]:
    """Ver `cmdi.validate_case`: misma rama `jobs <= 1`/`ctx is None`
    idéntica a siempre, misma rama paralela con el pool y el semáforo
    compartidos de `ctx`. Un mismo caso prueba lectura (`build_attempts`) y
    escritura (`build_write_attempts`) en una sola pasada: los intentos de
    ambas se combinan antes de validar, y `attempts_to_findings` distingue
    unos de otros por su `kind`."""
    case_id = Path(case_dir).name

    if jobs <= 1 or ctx is None:
        tools = run_harness(
            case_dir, image=image, timeout=discover_timeout, fs_root=fs_root, entry=entry,
            pythonpath=pythonpath, server_python=server_python,
        )
        attempts = build_attempts(tools, fs_root) + build_write_attempts(tools, fs_root)
        if not attempts:
            return [], [], []

        results = run_validate(
            case_dir, attempts, image=image, call_timeout=call_timeout, fs_root=fs_root,
            entry=entry, pythonpath=pythonpath, server_python=server_python,
        )
        return attempts_to_findings(case_id, attempts, results)

    with ctx.semaphore:
        discover_name = f"lynceus-sandbox-{uuid.uuid4().hex[:12]}"
        ctx.active.add_container(discover_name)
        try:
            tools = ctx.pool.submit(
                run_harness, case_dir, image=image, timeout=discover_timeout, fs_root=fs_root, entry=entry,
                pythonpath=pythonpath, server_python=server_python, container_name=discover_name,
            ).result()
        finally:
            kill_container(discover_name)
            ctx.active.discard_container(discover_name)

        attempts = build_attempts(tools, fs_root) + build_write_attempts(tools, fs_root)
        if not attempts:
            return [], [], []

        results = run_validate_split(
            case_dir, attempts, jobs=jobs, ctx=ctx, image=image, call_timeout=call_timeout, fs_root=fs_root,
            entry=entry, pythonpath=pythonpath, server_python=server_python,
        )
        return attempts_to_findings(case_id, attempts, results)
