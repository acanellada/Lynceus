from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class VulnClass(str, Enum):
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"


class Label(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    case: str
    vuln_class: VulnClass = Field(alias="class")
    tool: str
    file: str
    parameter: str


class ReproductionCall(BaseModel):
    """Una llamada tal cual se ejecutó durante la validación: nombre de tool
    y argumentos exactos, sin reconstruirla a partir de texto."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    arguments: dict[str, Any]


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case: str
    rule_id: str
    vuln_class: VulnClass
    tool: str
    severity: str
    message: str
    evidence: str | None = None
    validated: bool = False
    parameter: str | None = None
    technique: str | None = None
    payload: str | None = None
    reproduction: list[ReproductionCall] | None = None
