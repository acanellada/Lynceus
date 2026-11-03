"""Construye la imagen de un servidor objetivo: resuelve sus dependencias en
un contenedor aparte (nunca en el host) y genera una imagen que parte del
sandbox de validación sin tocar su entorno de Python.

No cambia nada de `runner.py`; reutiliza sus flags de endurecimiento y sus
comprobaciones de imagen/Docker (son correctas también aquí) en vez de
duplicarlas.
"""

from __future__ import annotations

import hashlib
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from lynceus_sec.validator.runner import (
    DEFAULT_IMAGE,
    _docker_available,
    _image_exists,
    _security_flags,
)

RESOLVER_IMAGE = "lynceus-resolver:0.1"
CACHE_ROOT = Path.home() / ".cache" / "lynceus" / "build"

RESOLVED_REQUIREMENTS_NAME = "requirements.resolved.txt"
WHEELS_DIRNAME = "wheels"
DOCKERFILE_NAME = "Dockerfile"

# `docker image inspect --format '{{.Architecture}}'` usa los nombres de Go
# ("arm64", "amd64"); `uv pip compile --python-platform` usa los triples de
# Rust ("aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu").
_PYTHON_PLATFORM_BY_ARCH = {
    "arm64": "aarch64-unknown-linux-gnu",
    "aarch64": "aarch64-unknown-linux-gnu",
    "amd64": "x86_64-unknown-linux-gnu",
    "x86_64": "x86_64-unknown-linux-gnu",
}

_TARGET_DOCKERFILE_TEMPLATE = """\
FROM {base_image}

USER root
COPY {requirements_name} /tmp/target-requirements.txt
COPY {wheels_dirname}/ /tmp/target-wheels/
RUN python -m venv /opt/target \\
    && /opt/target/bin/pip install --no-cache-dir --no-index --find-links=/tmp/target-wheels \\
         --require-hashes --only-binary=:all: -r /tmp/target-requirements.txt \\
    && rm -rf /tmp/target-requirements.txt /tmp/target-wheels \\
    && chown -R sandbox:sandbox /opt/target
USER sandbox
"""


class BuildError(RuntimeError):
    pass


@dataclass
class BuildResult:
    tag: str
    resolved_path: Path
    cache_dir: Path
    versions: list[tuple[str, str]]
    skipped_image_build: bool


def detect_target_platform(image: str = DEFAULT_IMAGE) -> str:
    """Arquitectura de `image` (la base del objetivo), traducida al valor que
    espera `uv pip compile --python-platform`. Falla con un error claro si no
    se puede determinar, en vez de asumir una arquitectura por defecto."""
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Architecture}}", image],
            check=False, capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BuildError(f"No se pudo determinar la arquitectura de {image!r}: {exc}") from exc

    arch = proc.stdout.strip()
    if proc.returncode != 0 or not arch:
        detail = proc.stderr.strip() or f"código de salida {proc.returncode}"
        raise BuildError(f"No se pudo determinar la arquitectura de {image!r}: {detail}")

    platform = _PYTHON_PLATFORM_BY_ARCH.get(arch)
    if platform is None:
        raise BuildError(
            f"Arquitectura {arch!r} de la imagen {image!r} desconocida; "
            f"no se puede fijar --python-platform (soportadas: {sorted(_PYTHON_PLATFORM_BY_ARCH)})"
        )
    return platform


def cache_id(target: Path, requirements: str, resolve_date: str | None) -> str:
    """Identificador determinista: mismas entradas, misma carpeta de caché
    (y por tanto se reaprovecha en vez de reconstruir desde cero)."""
    key = f"{Path(target).resolve()}::{requirements}::{resolve_date or ''}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def cache_dir_for(
    target: Path, requirements: str, resolve_date: str | None, *, cache_root: Path = CACHE_ROOT
) -> Path:
    return Path(cache_root) / cache_id(target, requirements, resolve_date)


def ensure_cache_dir_outside_target(cache_dir: Path, target: Path) -> None:
    """La caché deriva de $HOME, nunca de la carpeta analizada, pero se
    comprueba también en tiempo de ejecución (defensa en profundidad) por si
    alguien pasa como `target` una carpeta que contiene la propia caché."""
    cache_resolved = Path(cache_dir).absolute()
    target_resolved = Path(target).resolve()
    if cache_resolved == target_resolved or target_resolved in cache_resolved.parents:
        raise BuildError(
            f"El directorio de caché {cache_dir} cae dentro de la carpeta analizada {target}; se aborta."
        )


def build_resolve_command(
    requirements_path: Path,
    output_dir: Path,
    *,
    python_platform: str,
    resolve_date: str | None = None,
    image: str = RESOLVER_IMAGE,
    memory: str = "512m",
    cpus: str = "2",
    pids_limit: int = 128,
    container_name: str | None = None,
) -> tuple[str, list[str]]:
    """Comando de resolución: mismo endurecimiento que el sandbox de `scan`
    (vía `_security_flags`), pero sin `--network none` — este es el único
    paso de `lynceus build` con red permitida."""
    name = container_name or f"lynceus-resolve-{uuid.uuid4().hex[:12]}"
    cmd = [
        "docker", "run", "--rm",
        "--name", name,
        *_security_flags(memory, cpus, pids_limit, home="/tmp"),
        "-v", f"{Path(requirements_path).resolve()}:/resolve/requirements.in:ro",
        "-v", f"{Path(output_dir).resolve()}:/resolve/out:rw",
        image,
        "uv", "pip", "compile", "/resolve/requirements.in",
        "--python-version", "3.12",
        "--python-platform", python_platform,
        "--generate-hashes",
        "--no-build",
        "-o", f"/resolve/out/{RESOLVED_REQUIREMENTS_NAME}",
    ]
    if resolve_date:
        cmd += ["--exclude-newer", resolve_date]
    return name, cmd


def build_download_command(
    output_dir: Path,
    *,
    image: str = RESOLVER_IMAGE,
    memory: str = "512m",
    cpus: str = "2",
    pids_limit: int = 128,
    container_name: str | None = None,
) -> tuple[str, list[str]]:
    """Descarga las ruedas ya resueltas y con hash fijado, para que la
    construcción de la imagen objetivo (`docker build`) pueda ir sin red.
    Si una dependencia solo existe como código fuente, `pip download` falla
    aquí (sin red en la imagen objetivo, nada que construir) y su mensaje ya
    nombra el paquete."""
    name = container_name or f"lynceus-download-{uuid.uuid4().hex[:12]}"
    cmd = [
        "docker", "run", "--rm",
        "--name", name,
        *_security_flags(memory, cpus, pids_limit, home="/tmp"),
        "-v", f"{Path(output_dir).resolve()}:/resolve/out:rw",
        image,
        "python", "-m", "pip", "download",
        "--no-deps",
        "--require-hashes",
        "--only-binary=:all:",
        "-r", f"/resolve/out/{RESOLVED_REQUIREMENTS_NAME}",
        "-d", f"/resolve/out/{WHEELS_DIRNAME}",
    ]
    return name, cmd


def render_target_dockerfile(base_image: str = DEFAULT_IMAGE) -> str:
    return _TARGET_DOCKERFILE_TEMPLATE.format(
        base_image=base_image,
        requirements_name=RESOLVED_REQUIREMENTS_NAME,
        wheels_dirname=WHEELS_DIRNAME,
    )


def build_target_image_command(context_dir: Path, tag: str) -> list[str]:
    """Construye la imagen objetivo sin red: las ruedas ya están en
    `context_dir` con hash verificado, no hace falta ninguna descarga más."""
    return [
        "docker", "build",
        "--network", "none",
        "-f", str(Path(context_dir) / DOCKERFILE_NAME),
        "-t", tag,
        str(context_dir),
    ]


def compute_target_tag(resolved_path: Path) -> str:
    digest = hashlib.sha256(Path(resolved_path).read_bytes()).hexdigest()[:12]
    return f"lynceus-target:{digest}"


def parse_pinned_versions(resolved_text: str) -> list[tuple[str, str]]:
    """Lee los `nombre==versión` de un fichero resuelto por `uv pip compile`,
    ignorando las líneas de `--hash=...` (indentadas) y los comentarios."""
    versions: list[tuple[str, str]] = []
    for line in resolved_text.splitlines():
        if not line or line[0].isspace() or line.startswith("#"):
            continue
        token = line.split()[0]
        if "==" not in token:
            continue
        name, _, version = token.partition("==")
        versions.append((name, version))
    return versions


def _check_images(resolver_image: str, base_image: str) -> None:
    if not _docker_available():
        raise BuildError("Docker no está disponible en el PATH")
    if not _image_exists(resolver_image):
        raise BuildError(
            f"La imagen {resolver_image!r} no existe; constrúyela con "
            f"'docker build -t {resolver_image} sandbox/resolver/'"
        )
    if not _image_exists(base_image):
        raise BuildError(
            f"La imagen {base_image!r} no existe; constrúyela con 'docker build -t {base_image} sandbox/'"
        )


def _run_or_raise(cmd: list[str], container_name: str, step: str, *, timeout: float) -> None:
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        subprocess.run(["docker", "kill", container_name], check=False, capture_output=True)
        raise BuildError(f"{step} no terminó en {timeout}s") from exc

    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"código de salida {proc.returncode}"
        raise BuildError(f"{step} falló: {detail}")


def run_build(
    target: Path,
    requirements: str,
    *,
    resolve_date: str | None = None,
    cache_root: Path = CACHE_ROOT,
    resolver_image: str = RESOLVER_IMAGE,
    base_image: str = DEFAULT_IMAGE,
    resolve_timeout: float = 120.0,
    download_timeout: float = 180.0,
    build_timeout: float = 60.0,
) -> BuildResult:
    _check_images(resolver_image, base_image)
    python_platform = detect_target_platform(base_image)

    cache_dir = cache_dir_for(target, requirements, resolve_date, cache_root=cache_root)
    ensure_cache_dir_outside_target(cache_dir, target)
    cache_dir.mkdir(parents=True, exist_ok=True)

    requirements_path = Path(target) / requirements
    name, cmd = build_resolve_command(
        requirements_path, cache_dir, python_platform=python_platform,
        resolve_date=resolve_date, image=resolver_image,
    )
    _run_or_raise(cmd, name, "La resolución de dependencias", timeout=resolve_timeout)

    resolved_path = cache_dir / RESOLVED_REQUIREMENTS_NAME

    name, cmd = build_download_command(cache_dir, image=resolver_image)
    _run_or_raise(cmd, name, "La descarga de las ruedas resueltas", timeout=download_timeout)

    tag = compute_target_tag(resolved_path)
    versions = parse_pinned_versions(resolved_path.read_text())

    if _image_exists(tag):
        return BuildResult(
            tag=tag, resolved_path=resolved_path, cache_dir=cache_dir,
            versions=versions, skipped_image_build=True,
        )

    (cache_dir / DOCKERFILE_NAME).write_text(render_target_dockerfile(base_image))
    cmd = build_target_image_command(cache_dir, tag)
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=build_timeout)
    except subprocess.TimeoutExpired as exc:
        raise BuildError(f"La construcción de la imagen objetivo no terminó en {build_timeout}s") from exc
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"código de salida {proc.returncode}"
        raise BuildError(f"La construcción de la imagen objetivo falló: {detail}")

    return BuildResult(
        tag=tag, resolved_path=resolved_path, cache_dir=cache_dir,
        versions=versions, skipped_image_build=False,
    )
