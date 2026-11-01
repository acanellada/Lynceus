"""Genera y ejecuta intentos de SSRF sobre un caso, con receptor de canarios
en una red Docker interna.

Misma estructura que cmdi.py y ptrav.py en la forma pública (`build_attempts`,
`attempts_to_findings`, `validate_case`), pero el oráculo tiene dos partes:
el harness, dentro del contenedor del servidor, solo puede confirmar la carga
`file://` (igual que path traversal); la confirmación de las cargas de URL
depende del registro del receptor, que vive fuera del servidor analizado y
se lee aquí, en el host, después de que terminen los intentos.

Limitación conocida: `_neutral_value`, `_string_params` y `_base_arguments`
se reutilizan tal cual desde `ptrav.py` aunque son funciones privadas de ese
módulo; deberían moverse a un módulo común en vez de importarse así.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from lynceus_sec.core.model import Finding, VulnClass
from lynceus_sec.validator.payloads import build_ssrf_payloads
from lynceus_sec.validator.ptrav import _base_arguments, _neutral_value, _string_params
from lynceus_sec.validator.runner import (
    DEFAULT_IMAGE,
    check_network_isolation,
    create_internal_network,
    kill_container,
    read_receiver_log,
    remove_network,
    run_harness,
    run_validate,
    start_receiver,
    stop_receiver,
)

# Solo ModuleNotFoundError cuenta como fallo de entorno ajeno a esta clase;
# errores de conexión o "url no permitida" son resultados negativos normales.
_ENVIRONMENT_MARKERS = ("modulenotfounderror",)


def _secondary_arguments(tool: dict[str, Any], primary_arguments: dict[str, Any]) -> dict[str, Any]:
    """Para el segundo paso: reutiliza por nombre de parámetro TODOS los
    valores de la primera llamada (la carga y los neutros); si un parámetro
    de esta tool no apareció allí, un valor neutro propio."""
    schema = tool.get("input_schema", {})
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    return {
        name: primary_arguments[name] if name in primary_arguments else _neutral_value(properties[name])
        for name in required
        if name in properties
    }


def build_attempts(tools: list[dict[str, Any]], receiver_name: str, receiver_ip: str) -> list[dict[str, Any]]:
    """Un intento por cada (parámetro de tipo string, carga) de cada tool.

    Cada intento es, en una sola sesión del servidor: la llamada con la carga
    a la tool objetivo, seguida de una llamada a cada una de las demás tools
    (segundo paso). El hallazgo siempre se atribuye a la tool y el parámetro
    que recibieron la carga, nunca a las tools del segundo paso.
    """
    attempts: list[dict[str, Any]] = []
    for tool in tools:
        other_tools = [other for other in tools if other["name"] != tool["name"]]
        for param in _string_params(tool):
            for payload in build_ssrf_payloads(receiver_name, receiver_ip):
                primary_arguments = _base_arguments(tool, skip=param)
                primary_arguments[param] = payload.value
                calls = [{"tool": tool["name"], "arguments": primary_arguments}]
                calls += [
                    {"tool": other["name"], "arguments": _secondary_arguments(other, primary_arguments)}
                    for other in other_tools
                ]
                attempts.append(
                    {
                        "id": uuid.uuid4().hex,
                        "tool": tool["name"],
                        "parameter": param,
                        "technique": payload.technique,
                        "payload": payload.value,
                        "token": payload.token,
                        "canary_path": payload.canary_path,
                        "canary_content": payload.canary_content,
                        "environment_markers": _ENVIRONMENT_MARKERS,
                        "calls": calls,
                    }
                )
    return attempts


def _token_seen(token: str, log_entries: list[dict[str, Any]]) -> bool:
    return any(token in str(entry.get("path", "")) for entry in log_entries)


def attempts_to_findings(
    case_id: str,
    attempts: list[dict[str, Any]],
    results: list[dict[str, Any]],
    log_entries: list[dict[str, Any]] | None = None,
) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Solo los intentos `confirmed` producen Findings; `inconclusive` aparte.

    Un token visto en el registro del receptor confirma el intento sin
    importar lo que haya devuelto el harness (el oráculo manda sobre
    cualquier error de herramienta posterior a la petición real).
    """
    log_entries = log_entries or []
    results_by_id = {result["id"]: result for result in results}
    findings: list[Finding] = []
    inconclusive: list[dict[str, Any]] = []

    for attempt in attempts:
        result = results_by_id.get(attempt["id"])
        status = result["status"] if result is not None else "inconclusive"
        detail = result.get("detail") if result is not None else "sin resultado del harness"

        token = attempt.get("token")
        if token and _token_seen(token, log_entries):
            status, detail = "confirmed", "token visto en el registro del receptor"

        if status == "confirmed":
            findings.append(
                Finding(
                    case=case_id,
                    rule_id=f"ssrf-{attempt['technique']}",
                    vuln_class=VulnClass.SSRF,
                    tool=attempt["tool"],
                    severity="high",
                    message=(
                        f"SSRF confirmado en el parámetro {attempt['parameter']!r} "
                        f"de la tool {attempt['tool']!r} ({attempt['technique']})"
                    ),
                    evidence=f"payload={attempt['payload']!r} detail={detail}",
                    validated=True,
                )
            )
        elif status == "inconclusive":
            inconclusive.append({**attempt, "status": status, "detail": detail})
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
    network = create_internal_network()
    receiver_name: str | None = None
    discover_name = f"lynceus-sandbox-{uuid.uuid4().hex[:12]}"
    validate_name = f"lynceus-sandbox-{uuid.uuid4().hex[:12]}"
    try:
        check_network_isolation(network, image=image)
        receiver_name, receiver_ip = start_receiver(network, image=image)
        try:
            tools = run_harness(
                case_dir, image=image, timeout=discover_timeout,
                network=network, container_name=discover_name,
            )
            attempts = build_attempts(tools, receiver_name, receiver_ip)
            if not attempts:
                return [], []

            results = run_validate(
                case_dir, attempts, image=image, call_timeout=call_timeout,
                network=network, container_name=validate_name,
            )
            log_entries = read_receiver_log(receiver_name)
            return attempts_to_findings(case_id, attempts, results, log_entries)
        finally:
            # También ante KeyboardInterrupt: el contenedor del servidor
            # (descubrimiento o validación) se mata por nombre antes de
            # soltar el receptor y la red.
            kill_container(discover_name)
            kill_container(validate_name)
    finally:
        if receiver_name is not None:
            stop_receiver(receiver_name)
        remove_network(network)
