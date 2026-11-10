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
    build_positive_control_payload,
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


def attempts_to_findings(
    case_id: str,
    attempts: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> tuple[list[Finding], list[dict[str, Any]], list[dict[str, Any]]]:
    """Solo los intentos `confirmed` de tipo `traversal` producen Findings; los
    `inconclusive` se devuelven aparte. Los intentos `positive_control` nunca
    producen Finding ni cuentan como inconclusos: se devuelven en una tercera
    lista, con su resultado tal cual, puramente informativa."""
    results_by_id = {result["id"]: result for result in results}
    findings: list[Finding] = []
    inconclusive: list[dict[str, Any]] = []
    positive_controls: list[dict[str, Any]] = []

    for attempt in attempts:
        kind = attempt.get("kind", "traversal")
        result = results_by_id.get(attempt["id"])

        if kind == "positive_control":
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
            findings.append(
                Finding(
                    case=case_id,
                    rule_id=f"ptrav-{attempt['technique']}",
                    vuln_class=VulnClass.PATH_TRAVERSAL,
                    tool=attempt["tool"],
                    severity="high",
                    message=(
                        f"Path traversal confirmado en el parámetro "
                        f"{attempt['parameter']!r} de la tool {attempt['tool']!r} "
                        f"({attempt['technique']})"
                    ),
                    evidence=f"Contenido del canario leído en la respuesta: {attempt['canary_content']!r}",
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
    compartidos de `ctx`."""
    case_id = Path(case_dir).name

    if jobs <= 1 or ctx is None:
        tools = run_harness(
            case_dir, image=image, timeout=discover_timeout, fs_root=fs_root, entry=entry,
            pythonpath=pythonpath, server_python=server_python,
        )
        attempts = build_attempts(tools, fs_root)
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

        attempts = build_attempts(tools, fs_root)
        if not attempts:
            return [], [], []

        results = run_validate_split(
            case_dir, attempts, jobs=jobs, ctx=ctx, image=image, call_timeout=call_timeout, fs_root=fs_root,
            entry=entry, pythonpath=pythonpath, server_python=server_python,
        )
        return attempts_to_findings(case_id, attempts, results)
