"""Agregación de resultados compartida por los tres formatos de informe
(terminal, HTML, JSON): agrupa `Finding` en vulnerabilidades y expone los
nombres legibles de clase/gravedad. No depende de `rich` ni `typer`: cada
formato decide cómo escapar o sanear el texto que viene del servidor
analizado (`tool`, `parameter`, argumentos de reproducción, evidencia).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from lynceus_sec.core.model import Finding, ReproductionCall, VulnClass

CLASS_LABELS: dict[str, str] = {
    "command_injection": "Inyección de comandos",
    "path_traversal": "Path traversal",
    "ssrf": "SSRF",
}

SEVERITY_LABELS: dict[str, str] = {
    "critical": "Crítica",
    "high": "Alta",
}

SEVERITY_NOTE = "La gravedad se asigna por clase de vulnerabilidad; no es una puntuación CVSS."

SSRF_RECEIVER_NOTE = (
    "El receptor y su red son temporales: se crean para esta ejecución y se "
    "borran al terminar. Para reproducirlo, sustituye la URL del receptor "
    "por un receptor propio."
)

CAPABILITY_EXPLANATION = (
    "No es un fallo de implementación: la herramienta ejecuta comandos por "
    "diseño. Un agente manipulado podría usar esta capacidad para ejecutar "
    "comandos arbitrarios."
)


@dataclass
class FindingGroup:
    """Una vulnerabilidad: un (caso, herramienta, parámetro, clase), confirmada
    por una o más técnicas."""

    case: str
    tool: str
    parameter: str | None
    vuln_class: VulnClass
    severity: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def techniques(self) -> list[str]:
        seen: list[str] = []
        for finding in self.findings:
            if finding.technique and finding.technique not in seen:
                seen.append(finding.technique)
        return seen


def group_findings(findings: list[Finding]) -> list[FindingGroup]:
    """Agrupa por (case, tool, parameter, vuln_class), en orden de aparición.

    La clave usa `tool`/`parameter` tal cual (nunca interpretados): dos
    hallazgos solo caen en el mismo grupo si esos cuatro valores coinciden
    exactamente.
    """
    groups: dict[tuple[str, str, str | None, VulnClass], FindingGroup] = {}
    order: list[tuple[str, str, str | None, VulnClass]] = []

    for finding in findings:
        key = (finding.case, finding.tool, finding.parameter, finding.vuln_class)
        if key not in groups:
            groups[key] = FindingGroup(
                case=finding.case, tool=finding.tool, parameter=finding.parameter,
                vuln_class=finding.vuln_class, severity=finding.severity,
            )
            order.append(key)
        groups[key].findings.append(finding)

    return [groups[key] for key in order]


def format_call(call: ReproductionCall) -> str:
    args = ", ".join(f"{name}={value!r}" for name, value in call.arguments.items())
    return f"{call.tool}({args})"


def format_calls(calls: list[ReproductionCall] | None) -> list[str]:
    """Una cadena por llamada: para reproducciones de varios pasos (p. ej. SSRF),
    cada llamada va en su propia línea en vez de todas unidas en una sola."""
    if not calls:
        return ["(no disponible)"]
    return [format_call(call) for call in calls]


def format_reproduction(calls: list[ReproductionCall] | None) -> str:
    return "; ".join(format_calls(calls))


def count_phrase(count: int, singular: str, plural: str) -> str:
    """Concordancia de número: "1 vulnerabilidad confirmada" frente a
    "2 vulnerabilidades confirmadas"."""
    return f"{count} {singular if count == 1 else plural}"
