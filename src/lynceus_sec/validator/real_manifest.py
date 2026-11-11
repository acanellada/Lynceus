"""Manifiestos de servidores reales (`benchmark/real/*.toml`): un fichero por
vulnerabilidad real, con sus versiones (vulnerable y, si existe, corregida) y
los hallazgos `(tool, parameter)` esperados en cada una.

`expected` sale siempre del aviso (`advisory`, obligatorio) y del código del
commit, nunca de ejecutar Lynceus: comparar contra la propia herramienta que
se evalúa sería circular. Si el aviso nombra una herramienta que Lynceus no
puede confirmar (p. ej. una escritura, que su oráculo de path traversal no
lee de vuelta), ese hallazgo se incluye igual en `expected` y aparecerá como
falso negativo: el resultado correcto, no uno que haya que ocultar.

No todo fallo real tiene un CVE asignado (puede quedarse en un issue o un
GHSA sin número de CVE); por eso `cve` es opcional y `advisory` es el único
campo obligatorio que sostiene `expected`.

Formato, validado de forma estricta con pydantic (`tomllib` solo parsea):

    id = "cve-2026-7400"
    cve = "CVE-2026-7400"               # opcional: omítelo si el fallo no tiene CVE asignado
    advisory = "https://nvd.nist.gov/vuln/detail/CVE-2026-7400"  # obligatorio, solo https
    class = "path_traversal"            # command_injection | path_traversal | ssrf
    repo = "https://github.com/..."     # solo https
    subdir = "src/fetch"                # opcional, relativo al repo
    requirements = "pyproject.toml"     # relativo a repo/subdir
    entry = "server.py"                 # relativo a repo/subdir, termina en .py
    pythonpath = ["src"]                # opcional, relativo a repo/subdir
    fs_root = "/tmp/lynceus-root"       # opcional, solo path_traversal

    [[versions]]
    label = "vulnerable"
    commit = "<40 hex>"
    resolve_date = "2026-01-15"         # opcional; por defecto, fecha del commit
    expected = [{ tool = "read_file", parameter = "path" }]

    [[versions]]
    label = "fixed"
    commit = "<40 hex>"
    expected = []
"""

from __future__ import annotations

import re
import tomllib
from datetime import date
from pathlib import Path

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from lynceus_sec.core.model import VulnClass

ROOT = Path(__file__).resolve().parents[3]
REAL = ROOT / "benchmark" / "real"

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _as_relative(value: str, field_name: str) -> str:
    """Relativo, sin componentes '..' ni absoluto: mismo criterio que
    `cli._validate_entry`/`_validate_pythonpaths`/`_validate_requirements_path`
    para los campos equivalentes de `scan`/`build`, aplicado aquí al
    manifiesto en vez de a opciones de línea de comandos."""
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{field_name} {value!r} debe ser relativo, sin rutas absolutas ni '..'")
    return value


class ExpectedFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    parameter: str


class RealVersion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str
    commit: str
    resolve_date: str | None = None
    expected: list[ExpectedFinding] = Field(default_factory=list)

    @field_validator("commit")
    @classmethod
    def _validate_commit(cls, value: str) -> str:
        if not _SHA_RE.fullmatch(value):
            raise ValueError(
                f"commit {value!r} debe ser un SHA completo de 40 caracteres hexadecimales en minúsculas"
            )
        return value

    @field_validator("resolve_date")
    @classmethod
    def _validate_resolve_date(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError(f"resolve_date {value!r} debe tener el formato AAAA-MM-DD") from exc
        return value


class RealManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    cve: str | None = None
    advisory: str
    vuln_class: VulnClass = Field(alias="class")
    repo: str
    subdir: str | None = None
    requirements: str
    entry: str
    pythonpath: list[str] = Field(default_factory=list)
    fs_root: str | None = None
    versions: list[RealVersion]

    @field_validator("repo")
    @classmethod
    def _validate_repo(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError(f"repo {value!r} debe ser una URL https")
        return value

    @field_validator("advisory")
    @classmethod
    def _validate_advisory(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError(f"advisory {value!r} debe ser una URL https")
        return value

    @field_validator("subdir")
    @classmethod
    def _validate_subdir(cls, value: str | None) -> str | None:
        return None if value is None else _as_relative(value, "subdir")

    @field_validator("requirements")
    @classmethod
    def _validate_requirements(cls, value: str) -> str:
        return _as_relative(value, "requirements")

    @field_validator("entry")
    @classmethod
    def _validate_entry(cls, value: str) -> str:
        if not value.endswith(".py"):
            raise ValueError(f"entry {value!r} debe ser un fichero .py")
        return _as_relative(value, "entry")

    @field_validator("pythonpath")
    @classmethod
    def _validate_pythonpath(cls, value: list[str]) -> list[str]:
        return [_as_relative(item, "pythonpath") for item in value]

    @field_validator("fs_root")
    @classmethod
    def _validate_fs_root(cls, value: str | None) -> str | None:
        """Mismo criterio que `cli._validate_fs_root`: absoluto, bajo /tmp,
        sin '..' y distinto de /tmp mismo."""
        if value is None:
            return None
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError(f"fs_root {value!r} debe ser una ruta absoluta, sin componentes '..'")
        try:
            path.relative_to("/tmp")
        except ValueError as exc:
            raise ValueError(f"fs_root {value!r} debe estar bajo /tmp") from exc
        if path == Path("/tmp"):
            raise ValueError("fs_root no puede ser /tmp mismo; usa una subcarpeta")
        return value

    @model_validator(mode="after")
    def _validate_versions(self) -> RealManifest:
        if not self.versions:
            raise ValueError("un manifiesto necesita al menos una versión en 'versions'")
        labels = [v.label for v in self.versions]
        if len(labels) != len(set(labels)):
            raise ValueError(f"etiquetas de versión duplicadas en 'versions': {labels}")
        return self


def load_real_manifest(path: Path) -> RealManifest:
    raw = tomllib.loads(Path(path).read_text())
    try:
        return RealManifest.model_validate(raw)
    except ValidationError as exc:
        raise ValueError(f"Manifiesto inválido en {path}: {exc}") from exc


def load_real_manifests(real_dir: Path | None = None) -> list[RealManifest]:
    """Todos los manifiestos de `real_dir` (por defecto `benchmark/real`),
    en orden alfabético de fichero: determinista, con independencia del
    orden del sistema de ficheros."""
    real_dir = real_dir or REAL
    return [load_real_manifest(p) for p in sorted(real_dir.glob("*.toml"))]
