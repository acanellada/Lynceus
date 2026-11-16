"""Informe SARIF 2.1.0 de `lynceus scan`: JSON puro (biblioteca estándar, sin
dependencias de SARIF). Todo texto que venga del servidor analizado (nombre
de tool, parámetro, evidencia) se escribe tal cual como valor de cadena
JSON: `json.dumps` ya lo escapa correctamente, no se interpreta en ningún
momento.

`$schema` va en el nivel superior del `sarifLog` (no en el `run`): es donde
lo define el esquema oficial de SARIF 2.1.0 (`run` tiene
`additionalProperties: false` y no incluye `$schema` entre sus propiedades).
"""

from __future__ import annotations

from lynceus_sec.cli_env import EnvironmentInfo
from lynceus_sec.core.model import Finding, ReproductionCall, VulnClass
from lynceus_sec.report import CAPABILITY_EXPLANATION, CLASS_LABELS, group_findings

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json"
INFORMATION_URI = "https://github.com/acanellada/Lynceus"

CAPABILITY_RULE_ID = "lynceus/capability"

_RULE_ID_BY_CLASS: dict[VulnClass, str] = {
    VulnClass.COMMAND_INJECTION: "lynceus/command-injection",
    VulnClass.PATH_TRAVERSAL: "lynceus/path-traversal",
    VulnClass.SSRF: "lynceus/ssrf",
}

_CWE_BY_CLASS: dict[VulnClass, str] = {
    VulnClass.COMMAND_INJECTION: "CWE-78",
    VulnClass.PATH_TRAVERSAL: "CWE-22",
    VulnClass.SSRF: "CWE-918",
}

_SHORT_DESCRIPTION_BY_CLASS: dict[VulnClass, str] = {
    VulnClass.COMMAND_INJECTION: "Inyección de comandos del sistema a través de una herramienta MCP.",
    VulnClass.PATH_TRAVERSAL: "Lectura o escritura fuera del límite de sistema de ficheros previsto.",
    VulnClass.SSRF: "La herramienta realiza peticiones de red a un destino controlado por el atacante.",
}


def _vulnerability_rules() -> list[dict]:
    return [
        {
            "id": _RULE_ID_BY_CLASS[vuln_class],
            "name": CLASS_LABELS[vuln_class.value],
            "shortDescription": {"text": _SHORT_DESCRIPTION_BY_CLASS[vuln_class]},
            "defaultConfiguration": {"level": "error"},
            "properties": {"cwe": _CWE_BY_CLASS[vuln_class]},
        }
        for vuln_class in (VulnClass.COMMAND_INJECTION, VulnClass.PATH_TRAVERSAL, VulnClass.SSRF)
    ]


def _capability_rule() -> dict:
    return {
        "id": CAPABILITY_RULE_ID,
        "name": "Capacidad de ejecución",
        "shortDescription": {"text": CAPABILITY_EXPLANATION},
        "defaultConfiguration": {"level": "note"},
        "properties": {},
    }


def _artifact_location(target: str) -> dict:
    return {"locations": [{"physicalLocation": {"artifactLocation": {"uri": target}}}]}


def _logical_locations(tool: str, parameter: str | None) -> list[dict]:
    locations = [{"name": tool, "kind": "function"}]
    if parameter is not None:
        locations.append({"name": parameter, "kind": "parameter"})
    return locations


def _serialize_reproduction(calls: list[ReproductionCall] | None) -> list[dict]:
    return [call.model_dump() for call in (calls or [])]


def _vulnerability_result(group, target: str) -> dict:
    tool = group.tool
    parameter = group.parameter
    class_label = CLASS_LABELS.get(group.vuln_class.value, group.vuln_class.value)
    message = f"{class_label} confirmada en la herramienta '{tool}'"
    if parameter is not None:
        message += f", parámetro '{parameter}'"

    location = _artifact_location(target)
    location["locations"][0]["logicalLocations"] = _logical_locations(tool, parameter)

    return {
        "ruleId": _RULE_ID_BY_CLASS[group.vuln_class],
        "level": "error",
        "message": {"text": message},
        **location,
        "properties": {
            "tool": tool,
            "parameter": parameter,
            "techniques": group.techniques,
            "confirmations": [
                {
                    "technique": finding.technique,
                    "payload": finding.payload,
                    "evidence": finding.evidence,
                    "reproduction": _serialize_reproduction(finding.reproduction),
                }
                for finding in group.findings
            ],
        },
    }


def _serialize_capability_confirmation(confirmation: dict) -> dict:
    return {
        "technique": confirmation.get("technique"),
        "payload": confirmation.get("payload"),
        "evidence": confirmation.get("evidence"),
        "reproduction": _serialize_reproduction(confirmation.get("reproduction")),
    }


def _capability_result(class_name: str, item: dict, target: str) -> dict:
    tool = item.get("tool")
    parameter = item.get("parameter")
    class_label = CLASS_LABELS.get(class_name, class_name)
    message = f"Capacidad de ejecución ({class_label}) en la herramienta '{tool}'"
    if parameter is not None:
        message += f", parámetro '{parameter}'"

    location = _artifact_location(target)
    location["locations"][0]["logicalLocations"] = _logical_locations(tool, parameter)

    probe = item.get("probe")
    return {
        "ruleId": CAPABILITY_RULE_ID,
        "level": "note",
        "message": {"text": message},
        **location,
        "properties": {
            "tool": tool,
            "parameter": parameter,
            "probe": _serialize_capability_confirmation(probe) if probe else None,
            "confirmations": [
                _serialize_capability_confirmation(confirmation)
                for confirmation in item.get("confirmations", [])
            ],
            "bypassable_filter": item.get("bypassable_filter", False),
            "blocked_techniques": item.get("blocked_techniques", []),
        },
    }


def build_sarif_report(
    *,
    target: str,
    classes: list[str],
    fs_root: str,
    findings: list[Finding],
    inconclusive_by_class: dict[str, list[dict]],
    positive_controls_by_class: dict[str, list[dict]],
    capabilities_by_class: dict[str, list[dict]],
    elapsed_seconds: float,
    environment: EnvironmentInfo,
) -> dict:
    """`inconclusive_by_class` y `positive_controls_by_class` no generan
    `result`: un intento inconcluso no es un hallazgo ni una capacidad."""
    results = [_vulnerability_result(group, target) for group in group_findings(findings)]
    results.extend(
        _capability_result(class_name, item, target)
        for class_name, items in capabilities_by_class.items()
        for item in items
    )

    run = {
        "tool": {
            "driver": {
                "name": "Lynceus",
                "version": environment.lynceus_version,
                "informationUri": INFORMATION_URI,
                "rules": [*_vulnerability_rules(), _capability_rule()],
            }
        },
        "columnKind": "utf16CodeUnits",
        "automationDetails": {"id": target},
        "results": results,
    }

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [run],
    }
