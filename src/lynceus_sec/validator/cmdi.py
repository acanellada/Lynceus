"""Genera y ejecuta intentos de inyección de comandos/argumentos sobre un caso.

Todo se deduce de `list_tools` dentro del sandbox: ningún parámetro, nombre de
tool ni ruta es específico de un caso concreto.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from lynceus_sec.core.model import Finding, VulnClass
from lynceus_sec.validator.payloads import build_payloads
from lynceus_sec.validator.runner import DEFAULT_IMAGE, run_harness, run_validate

_NEUTRAL_BY_TYPE: dict[str, Any] = {
    "string": "lynceus",
    "integer": 0,
    "number": 0.0,
    "boolean": False,
    "array": [],
    "object": {},
}


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


def build_attempts(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Un intento por cada (parámetro de tipo string, carga) de cada tool."""
    attempts: list[dict[str, Any]] = []
    for tool in tools:
        for param in _string_params(tool):
            for payload in build_payloads():
                arguments = _base_arguments(tool, skip=param)
                arguments[param] = payload.value
                attempts.append(
                    {
                        "id": uuid.uuid4().hex,
                        "tool": tool["name"],
                        "parameter": param,
                        "technique": payload.technique,
                        "payload": payload.value,
                        "canary_path": payload.canary_path,
                        "arguments": arguments,
                    }
                )
    return attempts


def attempts_to_findings(
    case_id: str,
    attempts: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Solo los intentos `confirmed` producen Findings. Los `inconclusive` se devuelven aparte."""
    results_by_id = {result["id"]: result for result in results}
    findings: list[Finding] = []
    inconclusive: list[dict[str, Any]] = []

    for attempt in attempts:
        result = results_by_id.get(attempt["id"])
        if result is None:
            inconclusive.append({**attempt, "status": "inconclusive", "detail": "sin resultado del harness"})
            continue

        status = result["status"]
        if status == "confirmed":
            findings.append(
                Finding(
                    case=case_id,
                    rule_id=f"cmdi-{attempt['technique']}",
                    vuln_class=VulnClass.COMMAND_INJECTION,
                    tool=attempt["tool"],
                    severity="high",
                    message=(
                        f"Inyección de comandos confirmada en el parámetro "
                        f"{attempt['parameter']!r} de la tool {attempt['tool']!r} "
                        f"({attempt['technique']})"
                    ),
                    evidence=f"payload={attempt['payload']!r} canary={attempt['canary_path']}",
                    validated=True,
                )
            )
        elif status == "inconclusive":
            inconclusive.append({**attempt, **result})
        # not_confirmed: resultado negativo normal, ni Finding ni informe aparte

    return findings, inconclusive


def validate_case(
    case_dir: Path,
    *,
    image: str = DEFAULT_IMAGE,
    discover_timeout: float = 20.0,
    call_timeout: float = 15.0,
) -> tuple[list[Finding], list[dict[str, Any]]]:
    case_id = Path(case_dir).name
    tools = run_harness(case_dir, image=image, timeout=discover_timeout)
    attempts = build_attempts(tools)
    if not attempts:
        return [], []

    results = run_validate(case_dir, attempts, image=image, call_timeout=call_timeout)
    return attempts_to_findings(case_id, attempts, results)
