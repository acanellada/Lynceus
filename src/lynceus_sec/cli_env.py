"""Información del entorno para los informes: versión de Lynceus, imagen del
sandbox y versiones de Python/`mcp`.

Las versiones de Python y `mcp` se leen de `sandbox/Dockerfile` y
`sandbox/requirements.in` (los ficheros que fijan la imagen), nunca
comprobando un contenedor en marcha: por eso se exponen como "declaradas",
no como lo que de verdad corre en la imagen construida.

Solo lee esos ficheros e inspecciona la imagen por nombre (`docker image
inspect`); no construye ni ejecuta nada, y no toca las flags de `docker run`.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from lynceus_sec.validator.runner import DEFAULT_IMAGE

REPO_ROOT = Path(__file__).resolve().parents[2]
SANDBOX_DOCKERFILE = REPO_ROOT / "sandbox" / "Dockerfile"
SANDBOX_REQUIREMENTS_IN = REPO_ROOT / "sandbox" / "requirements.in"

_FROM_RE = re.compile(r"^FROM\s+(\S+)", re.MULTILINE)
_PYTHON_TAG_RE = re.compile(r"python:([0-9]+\.[0-9]+)")
_MCP_PIN_RE = re.compile(r"^mcp==([^\s]+)", re.MULTILINE)


@dataclass
class EnvironmentInfo:
    lynceus_version: str
    sandbox_image: str
    sandbox_image_id: str | None
    """`.Id` de `docker image inspect`: una imagen construida en local no
    tiene digest de repositorio, así que el identificador local es lo único
    estable que se puede mostrar para ella."""
    base_image_ref: str | None
    """Imagen base (con digest) tal como la fija el `FROM` de `sandbox/Dockerfile`."""
    declared_python_version: str | None
    declared_mcp_version: str | None
    target_image: str | None = None
    """Imagen en la que corrió el servidor analizado (`--image` de `scan`, o
    la propia imagen del sandbox si no se dio)."""
    target_image_id: str | None = None


def _package_version() -> str:
    try:
        return version("lynceus-sec")
    except PackageNotFoundError:
        return "desconocida (paquete no instalado)"


def _docker_image_id(image: str) -> str | None:
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image],
            check=False, capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    image_id = proc.stdout.strip()
    return image_id or None


def _dockerfile_text() -> str | None:
    try:
        return SANDBOX_DOCKERFILE.read_text()
    except OSError:
        return None


def _base_image_ref(dockerfile_text: str | None) -> str | None:
    if dockerfile_text is None:
        return None
    match = _FROM_RE.search(dockerfile_text)
    return match.group(1) if match else None


def _declared_python_version(dockerfile_text: str | None) -> str | None:
    if dockerfile_text is None:
        return None
    match = _PYTHON_TAG_RE.search(dockerfile_text)
    return match.group(1) if match else None


def _declared_mcp_version() -> str | None:
    try:
        text = SANDBOX_REQUIREMENTS_IN.read_text()
    except OSError:
        return None
    match = _MCP_PIN_RE.search(text)
    return match.group(1) if match else None


def collect_environment_info(image: str = DEFAULT_IMAGE, *, target_image: str | None = None) -> EnvironmentInfo:
    """`target_image` es la imagen objetivo (`--image` de `scan`); si no se da
    (no se usó `--image`), el servidor corrió en la propia imagen del
    sandbox, así que se reutiliza su id en vez de inspeccionarla dos veces."""
    dockerfile_text = _dockerfile_text()
    sandbox_image_id = _docker_image_id(image)
    resolved_target_image = target_image or image
    target_image_id = sandbox_image_id if resolved_target_image == image else _docker_image_id(resolved_target_image)
    return EnvironmentInfo(
        lynceus_version=_package_version(),
        sandbox_image=image,
        sandbox_image_id=sandbox_image_id,
        base_image_ref=_base_image_ref(dockerfile_text),
        declared_python_version=_declared_python_version(dockerfile_text),
        declared_mcp_version=_declared_mcp_version(),
        target_image=resolved_target_image,
        target_image_id=target_image_id,
    )
