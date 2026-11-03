"""Genera y ejecuta intentos de inyección de comandos/argumentos sobre un caso.

Todo se deduce de `list_tools` dentro del sandbox: ningún parámetro, nombre de
tool ni ruta es específico de un caso concreto.

Por cada (tool, parámetro) se añade también una sonda de capacidad (ver
`build_probe_payload`): un valor sin metacaracteres ("touch <canario>"). Si
esa sonda crea el canario, esa combinación se clasifica como capacidad de
ejecución de comandos por diseño, y sus confirmaciones de inyección se
agrupan bajo esa capacidad en vez de reportarse como vulnerabilidad.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from lynceus_sec.core.model import Finding, ReproductionCall, VulnClass
from lynceus_sec.validator.payloads import build_payloads, build_probe_payload
from lynceus_sec.validator.runner import (
    DEFAULT_ENTRY,
    DEFAULT_IMAGE,
    run_harness,
    run_validate,
)

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
    """Un intento por cada (parámetro de tipo string, carga) de cada tool, más
    una sonda de capacidad por (tool, parámetro): ver `kind` en cada intento
    ("injection" o "probe")."""
    attempts: list[dict[str, Any]] = []
    for tool in tools:
        for param in _string_params(tool):
            probe = build_probe_payload()
            probe_arguments = _base_arguments(tool, skip=param)
            probe_arguments[param] = probe.value
            attempts.append(
                {
                    "id": uuid.uuid4().hex,
                    "kind": "probe",
                    "tool": tool["name"],
                    "parameter": param,
                    "technique": probe.technique,
                    "payload": probe.value,
                    "canary_path": probe.canary_path,
                    "arguments": probe_arguments,
                }
            )
            for payload in build_payloads():
                arguments = _base_arguments(tool, skip=param)
                arguments[param] = payload.value
                attempts.append(
                    {
                        "id": uuid.uuid4().hex,
                        "kind": "injection",
                        "tool": tool["name"],
                        "parameter": param,
                        "technique": payload.technique,
                        "payload": payload.value,
                        "canary_path": payload.canary_path,
                        "arguments": arguments,
                    }
                )
    return attempts


def _confirmation(attempt: dict[str, Any]) -> dict[str, Any]:
    """Una confirmación (sonda o inyección) tal como se agrupa bajo una capacidad."""
    return {
        "technique": attempt["technique"],
        "payload": attempt["payload"],
        "evidence": f"Canario creado en {attempt['canary_path']}",
        "reproduction": [ReproductionCall(tool=attempt["tool"], arguments=attempt["arguments"])],
    }


def attempts_to_findings(
    case_id: str,
    attempts: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> tuple[list[Finding], list[dict[str, Any]], list[dict[str, Any]]]:
    """Solo los intentos `confirmed` producen Findings; los `inconclusive` se
    devuelven aparte. Si la sonda de capacidad (`kind="probe"`) se confirma
    para un (tool, parámetro), esa combinación se clasifica como capacidad:
    sus confirmaciones de inyección (`kind="injection"`) no generan Finding,
    se agrupan en `capabilities` junto con la propia sonda. Otras tools o
    parámetros del mismo servidor, sin sonda confirmada, siguen generando
    Finding como siempre."""
    results_by_id = {result["id"]: result for result in results}

    capability_keys = {
        (attempt["tool"], attempt["parameter"])
        for attempt in attempts
        if attempt.get("kind") == "probe"
        and (result := results_by_id.get(attempt["id"])) is not None
        and result["status"] == "confirmed"
    }

    findings: list[Finding] = []
    inconclusive: list[dict[str, Any]] = []
    capabilities_by_key: dict[tuple[str, str], dict[str, Any]] = {}

    def _capability_entry(attempt: dict[str, Any]) -> dict[str, Any]:
        key = (attempt["tool"], attempt["parameter"])
        return capabilities_by_key.setdefault(
            key,
            {"tool": attempt["tool"], "parameter": attempt["parameter"], "probe": None, "confirmations": []},
        )

    for attempt in attempts:
        kind = attempt.get("kind", "injection")
        key = (attempt["tool"], attempt["parameter"])
        result = results_by_id.get(attempt["id"])

        if result is None:
            inconclusive.append({**attempt, "status": "inconclusive", "detail": "sin resultado del harness"})
            continue

        status = result["status"]

        if kind == "probe":
            if status == "confirmed":
                _capability_entry(attempt)["probe"] = _confirmation(attempt)
            elif status == "inconclusive":
                inconclusive.append({**attempt, **result})
            # not_confirmed: ninguna capacidad, ninguna inconclusión
            continue

        if status == "confirmed":
            if key in capability_keys:
                _capability_entry(attempt)["confirmations"].append(_confirmation(attempt))
            else:
                findings.append(
                    Finding(
                        case=case_id,
                        rule_id=f"cmdi-{attempt['technique']}",
                        vuln_class=VulnClass.COMMAND_INJECTION,
                        tool=attempt["tool"],
                        severity="critical",
                        message=(
                            f"Inyección de comandos confirmada en el parámetro "
                            f"{attempt['parameter']!r} de la tool {attempt['tool']!r} "
                            f"({attempt['technique']})"
                        ),
                        evidence=f"Canario creado en {attempt['canary_path']}",
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

    return findings, inconclusive, list(capabilities_by_key.values())


def validate_case(
    case_dir: Path,
    *,
    image: str = DEFAULT_IMAGE,
    discover_timeout: float = 20.0,
    call_timeout: float = 15.0,
    entry: str = DEFAULT_ENTRY,
    pythonpath: list[str] | None = None,
    server_python: str | None = None,
) -> tuple[list[Finding], list[dict[str, Any]], list[dict[str, Any]]]:
    case_id = Path(case_dir).name
    tools = run_harness(
        case_dir, image=image, timeout=discover_timeout, entry=entry,
        pythonpath=pythonpath, server_python=server_python,
    )
    attempts = build_attempts(tools)
    if not attempts:
        return [], [], []

    results = run_validate(
        case_dir, attempts, image=image, call_timeout=call_timeout, entry=entry,
        pythonpath=pythonpath, server_python=server_python,
    )
    return attempts_to_findings(case_id, attempts, results)
