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

import hashlib
from pathlib import Path

from lynceus_sec.cli_env import EnvironmentInfo
from lynceus_sec.core.model import Finding, ReproductionCall, VulnClass
from lynceus_sec.report import CAPABILITY_EXPLANATION, CLASS_LABELS, group_findings
from lynceus_sec.validator.runner import DEFAULT_ENTRY

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json"
INFORMATION_URI = "https://github.com/acanellada/Lynceus"

CAPABILITY_RULE_ID = "lynceus/capability"

# Versionada: si el algoritmo de la huella cambia alguna vez, una clave nueva
# evita que GitHub confunda una huella vieja con la de un hallazgo distinto.
_FINGERPRINT_KEY = "lynceus/case-tool-parameter-class/v1"

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

_WHAT_BY_CLASS: dict[VulnClass, str] = {
    VulnClass.COMMAND_INJECTION: (
        "Una herramienta MCP pasa un parámetro a un comando del sistema (shell o "
        "exec) sin tratarlo como entrada no confiable, así que un agente "
        "manipulado puede ejecutar comandos arbitrarios en el servidor."
    ),
    VulnClass.PATH_TRAVERSAL: (
        "Una herramienta MCP usa un parámetro para construir una ruta de "
        "fichero sin comprobar que sigue dentro del directorio permitido, así "
        "que un agente manipulado puede leer o escribir fuera de ese límite."
    ),
    VulnClass.SSRF: (
        "Una herramienta MCP usa un parámetro para elegir el destino de una "
        "petición de red sin validarlo, así que un agente manipulado puede "
        "hacer que el servidor contacte con un destino de su elección "
        "(incluida la red interna)."
    ),
}

_HOW_CONFIRMED_BY_CLASS: dict[VulnClass, str] = {
    VulnClass.COMMAND_INJECTION: (
        "Lynceus creó un fichero con un nombre aleatorio (el canario) desde un "
        "comando inyectado en el parámetro, dentro de un sandbox Docker "
        "endurecido, y comprobó que el fichero existe tras la llamada."
    ),
    VulnClass.PATH_TRAVERSAL: (
        "Lynceus intentó leer o escribir un fichero fuera del límite declarado "
        "(--fs-root) con un canario de contenido aleatorio, dentro de un "
        "sandbox Docker endurecido, y comprobó que el contenido aparece en la "
        "respuesta o que el fichero existe en la ruta de escape."
    ),
    VulnClass.SSRF: (
        "Lynceus montó un receptor HTTP en una red interna sin salida y "
        "comprobó que recibía la petición, con un token único por intento, "
        "cuando la herramienta usaba el parámetro como destino."
    ),
}

_HOW_TO_FIX_BY_CLASS: dict[VulnClass, str] = {
    VulnClass.COMMAND_INJECTION: (
        "Evita construir un comando de shell con el parámetro: usa `subprocess` "
        "con una lista de argumentos (`shell=False`) y valida o limita a una "
        "lista cerrada los valores aceptados."
    ),
    VulnClass.PATH_TRAVERSAL: (
        "Resuelve la ruta (sin seguir enlaces simbólicos que escapen del "
        "límite) y comprueba que sigue dentro del directorio permitido antes "
        "de leer o escribir, rechazando la llamada si no es así."
    ),
    VulnClass.SSRF: (
        "Valida el destino contra una lista de hosts permitidos antes de "
        "conectar, y rechaza IPs privadas, de loopback y de metadatos (y sus "
        "redirecciones)."
    ),
}


def _cwe_url(cwe_id: str) -> str:
    number = cwe_id.removeprefix("CWE-")
    return f"https://cwe.mitre.org/data/definitions/{number}.html"


def _vulnerability_help(vuln_class: VulnClass) -> dict:
    cwe_id = _CWE_BY_CLASS[vuln_class]
    cwe_url = _cwe_url(cwe_id)
    text = (
        f"Qué es: {_WHAT_BY_CLASS[vuln_class]}\n\n"
        f"Cómo se confirmó: {_HOW_CONFIRMED_BY_CLASS[vuln_class]}\n\n"
        f"Cómo corregirla: {_HOW_TO_FIX_BY_CLASS[vuln_class]}\n\n"
        f"{cwe_id}: {cwe_url}"
    )
    markdown = (
        f"**Qué es:** {_WHAT_BY_CLASS[vuln_class]}\n\n"
        f"**Cómo se confirmó:** {_HOW_CONFIRMED_BY_CLASS[vuln_class]} "
        "Ver `confirmations` en las propiedades de este resultado para la "
        "técnica, la carga y la evidencia exactas.\n\n"
        f"**Cómo corregirla:** {_HOW_TO_FIX_BY_CLASS[vuln_class]}\n\n"
        f"**[{cwe_id}]({cwe_url})**"
    )
    return {"text": text, "markdown": markdown}


def _capability_help() -> dict:
    text = (
        f"{CAPABILITY_EXPLANATION}\n\n"
        "No hace falta corregir nada: si esta capacidad no es intencionada, "
        "quítala o restríngela; si lo es, trata su entrada como no confiable "
        "en el resto del servidor."
    )
    markdown = (
        f"{CAPABILITY_EXPLANATION}\n\n"
        "No hace falta corregir nada: si esta capacidad no es intencionada, "
        "quítala o restríngela; si lo es, trata su entrada como no confiable "
        "en el resto del servidor."
    )
    return {"text": text, "markdown": markdown}


def _vulnerability_rules() -> list[dict]:
    return [
        {
            "id": _RULE_ID_BY_CLASS[vuln_class],
            "name": CLASS_LABELS[vuln_class.value],
            "shortDescription": {"text": _SHORT_DESCRIPTION_BY_CLASS[vuln_class]},
            "help": _vulnerability_help(vuln_class),
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
        "help": _capability_help(),
        "defaultConfiguration": {"level": "note"},
        "properties": {},
    }


def _artifact_uri(target: str, entry: str, sarif_root: str | None) -> str:
    """Ruta del fichero de entrada dentro de `target`. Si `sarif_root` se da
    y `target` cae dentro de ella, la URI se escribe relativa a esa raíz (así
    GitHub la enlaza con el fichero del repositorio que invoca el scan);
    si no, o si `target` queda fuera, se usa la ruta completa tal cual
    (nunca se construye una URI con componentes '..')."""
    full_path = Path(target) / entry
    if sarif_root is not None:
        try:
            relative = full_path.resolve().relative_to(Path(sarif_root).resolve())
        except ValueError:
            relative = None
        if relative is not None:
            return relative.as_posix()
    return full_path.as_posix()


def _artifact_location(target: str, entry: str, sarif_root: str | None) -> dict:
    uri = _artifact_uri(target, entry, sarif_root)
    return {"locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]}


def _fingerprint(case: str, tool: str, parameter: str | None, class_name: str) -> dict:
    # "\x1f" (separador de unidad) nunca aparece en nombres de tool/parameter
    # legítimos, así que no hay colisiones tipo ("a|b", "c") vs ("a", "b|c").
    digest_input = "\x1f".join((case, tool, parameter or "", class_name))
    digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()
    return {_FINGERPRINT_KEY: digest}


def _logical_locations(tool: str, parameter: str | None) -> list[dict]:
    locations = [{"name": tool, "kind": "function"}]
    if parameter is not None:
        locations.append({"name": parameter, "kind": "parameter"})
    return locations


def _serialize_reproduction(calls: list[ReproductionCall] | None) -> list[dict]:
    return [call.model_dump() for call in (calls or [])]


def _vulnerability_result(group, target: str, entry: str, sarif_root: str | None) -> dict:
    tool = group.tool
    parameter = group.parameter
    class_label = CLASS_LABELS.get(group.vuln_class.value, group.vuln_class.value)
    message = f"{class_label} confirmada en la herramienta '{tool}'"
    if parameter is not None:
        message += f", parámetro '{parameter}'"

    location = _artifact_location(target, entry, sarif_root)
    location["locations"][0]["logicalLocations"] = _logical_locations(tool, parameter)

    return {
        "ruleId": _RULE_ID_BY_CLASS[group.vuln_class],
        "level": "error",
        "message": {"text": message},
        **location,
        "partialFingerprints": _fingerprint(group.case, tool, parameter, group.vuln_class.value),
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


def _capability_result(class_name: str, item: dict, target: str, entry: str, sarif_root: str | None, case: str) -> dict:
    tool = item.get("tool")
    parameter = item.get("parameter")
    class_label = CLASS_LABELS.get(class_name, class_name)
    message = f"Capacidad de ejecución ({class_label}) en la herramienta '{tool}'"
    if parameter is not None:
        message += f", parámetro '{parameter}'"

    location = _artifact_location(target, entry, sarif_root)
    location["locations"][0]["logicalLocations"] = _logical_locations(tool, parameter)

    probe = item.get("probe")
    return {
        "ruleId": CAPABILITY_RULE_ID,
        "level": "note",
        "message": {"text": message},
        **location,
        "partialFingerprints": _fingerprint(case, tool, parameter, class_name),
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
    entry: str = DEFAULT_ENTRY,
    sarif_root: str | None = None,
    findings: list[Finding],
    inconclusive_by_class: dict[str, list[dict]],
    positive_controls_by_class: dict[str, list[dict]],
    capabilities_by_class: dict[str, list[dict]],
    elapsed_seconds: float,
    environment: EnvironmentInfo,
) -> dict:
    """`inconclusive_by_class` y `positive_controls_by_class` no generan
    `result`: un intento inconcluso no es un hallazgo ni una capacidad.

    `entry` es el fichero de entrada del servidor (el `--entry` de `scan`)
    dentro de `target`: la ubicación apunta a ese fichero, no a la carpeta.
    `sarif_root`, si se da, es la ruta a la que escribir la URI relativa
    (ver `_artifact_uri`)."""
    case = Path(target).name
    results = [_vulnerability_result(group, target, entry, sarif_root) for group in group_findings(findings)]
    results.extend(
        _capability_result(class_name, item, target, entry, sarif_root, case)
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
