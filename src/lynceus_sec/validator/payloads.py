"""Cargas fijas de inyección de comandos/argumentos y de path traversal. Sin LLM.

Cada carga lleva su propio canario en /tmp, comprobado por el harness, nunca
por el servidor analizado. Para inyección de comandos, cada técnica se genera
en dos variantes: "bare" (la carga sola) y "prefixed" (con un prefijo inocuo
delante, p.ej. "lynceus; touch <canario>"), porque un valor que empieza
directamente por un separador puede comportarse distinto a uno que primero
parece un valor normal.
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


def _random_canary_content() -> str:
    return f"lynceus-secret-{uuid.uuid4().hex}"


def build_payloads() -> list[Payload]:
    """Devuelve las cargas fijas, cada una con un canario nuevo y único."""
    payloads: list[Payload] = []
    for technique, template in _TEMPLATES.items():
        for variant, prefix in (("bare", ""), ("prefixed", _INNOCUOUS_PREFIX)):
            canary = _random_canary_path()
            value = prefix + template.format(canary=canary)
            payloads.append(Payload(technique=f"{technique}_{variant}", canary_path=canary, value=value))
    return payloads


_TRAVERSAL_DEPTH = 8


@dataclass(frozen=True)
class PathPayload:
    technique: str
    canary_path: str
    canary_content: str
    value: str


def build_path_traversal_payloads(depth: int = _TRAVERSAL_DEPTH) -> list[PathPayload]:
    """Cargas fijas de path traversal, cada una con su propio canario de
    lectura: nombre y contenido se generan por separado (independientes),
    para que un servidor que repita la ruta en un mensaje de error no cuente
    como fuga de contenido.
    """
    traversal_prefix = "../" * depth
    payloads: list[PathPayload] = []
    for technique in ("absolute", "dotdot_bare", "dotdot_dotslash"):
        canary_path = _random_canary_path()
        canary_content = _random_canary_content()
        relative_canary = canary_path.removeprefix("/")
        if technique == "absolute":
            value = canary_path
        elif technique == "dotdot_bare":
            value = f"{traversal_prefix}{relative_canary}"
        else:
            value = f"./{traversal_prefix}{relative_canary}"
        payloads.append(
            PathPayload(technique=technique, canary_path=canary_path, canary_content=canary_content, value=value)
        )
    return payloads
