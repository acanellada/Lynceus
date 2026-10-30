"""Cargas fijas de inyección de comandos y de argumentos. Sin LLM.

Cada carga lleva un canario de nombre aleatorio en /tmp (comprobado por el
harness, nunca por el servidor analizado). Cada técnica se genera en dos
variantes: "bare" (la carga sola) y "prefixed" (con un prefijo inocuo delante,
p.ej. "lynceus; touch <canario>"), porque un valor que empieza directamente
por un separador puede comportarse distinto a uno que primero parece un
valor normal.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

_INNOCUOUS_PREFIX = "lynceus"

_TEMPLATES: dict[str, str] = {
    "shell_semicolon": "; touch {canary}",
    "shell_and": "&& touch {canary}",
    "shell_pipe": "| touch {canary}",
    "shell_newline": "\ntouch {canary}",
    "command_substitution": "$(touch {canary})",
    "backticks": "`touch {canary}`",
    "argument_injection_output": "--output={canary}",
}


@dataclass(frozen=True)
class Payload:
    technique: str
    canary_path: str
    value: str


def _random_canary_path() -> str:
    return f"/tmp/lynceus-canary-{uuid.uuid4().hex}"


def build_payloads() -> list[Payload]:
    """Devuelve las cargas fijas, cada una con un canario nuevo y único."""
    payloads: list[Payload] = []
    for technique, template in _TEMPLATES.items():
        for variant, prefix in (("bare", ""), ("prefixed", _INNOCUOUS_PREFIX)):
            canary = _random_canary_path()
            value = prefix + template.format(canary=canary)
            payloads.append(Payload(technique=f"{technique}_{variant}", canary_path=canary, value=value))
    return payloads
