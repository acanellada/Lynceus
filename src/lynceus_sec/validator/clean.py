"""Limpia las imágenes `lynceus-target:*` y la caché de construcción de
Lynceus acumuladas en el host tras usar `lynceus build` repetidamente.

Nunca toca `lynceus-sandbox` ni `lynceus-resolver`: solo pide a Docker las
imágenes que casan con `reference=lynceus-target:*` y, como defensa en
profundidad, vuelve a filtrar el resultado con `build.TARGET_IMAGE_RE`.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from lynceus_sec.validator.build import (
    TARGET_IMAGE_RE,
    cache_base_dir,
    default_cache_root,
)
from lynceus_sec.validator.runner import _docker_responding

_TARGET_IMAGE_FILTER = "reference=lynceus-target:*"


class CleanError(RuntimeError):
    pass


@dataclass(frozen=True)
class TargetImage:
    tag: str
    size: str


def ensure_docker_responding() -> None:
    """Pura validación, sin efectos: ni lista ni borra nada. Pensada para
    comprobarse antes de cualquier operación destructiva de `clean`."""
    if not _docker_responding():
        raise CleanError("Docker no responde: ¿está en marcha?")


def list_target_images() -> list[TargetImage]:
    """Imágenes `lynceus-target:<12 hex>` locales, con el tamaño tal cual lo
    reporta `docker images` (no se reimplementa el cálculo de bytes)."""
    ensure_docker_responding()
    proc = subprocess.run(
        ["docker", "images", "--filter", _TARGET_IMAGE_FILTER, "--format", "{{.Repository}}:{{.Tag}}\t{{.Size}}"],
        check=False, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or f"código de salida {proc.returncode}"
        raise CleanError(f"No se pudieron listar las imágenes lynceus-target: {detail}")

    images: list[TargetImage] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        tag, _, size = line.partition("\t")
        if TARGET_IMAGE_RE.fullmatch(tag):
            images.append(TargetImage(tag=tag, size=size.strip()))
    return images


def remove_images(tags: list[str]) -> tuple[list[str], list[str]]:
    """Borra cada imagen con `docker rmi` (una a una, mejor esfuerzo: una
    puede estar en uso por un contenedor). Devuelve `(borradas, fallidas)`."""
    removed: list[str] = []
    failed: list[str] = []
    for tag in tags:
        proc = subprocess.run(["docker", "rmi", tag], check=False, capture_output=True, text=True)
        if proc.returncode == 0:
            removed.append(tag)
        else:
            failed.append(tag)
    return removed, failed


def _ensure_safe_build_cache_dir(cache_dir: Path) -> None:
    """Se niega a borrar `cache_dir` si no es, con toda certeza, la
    subcarpeta `build` de la caché de Lynceus: nunca su base (p.ej. si
    `LYNCEUS_CACHE_DIR` apuntara por error a `$HOME`, borrar `~/build`
    podría destruir una carpeta ajena a Lynceus), ni la raíz del sistema de
    ficheros."""
    resolved = cache_dir.resolve()
    base_resolved = cache_base_dir().resolve()
    home_resolved = Path.home().resolve()

    if base_resolved == home_resolved:
        raise CleanError(
            f"La base de la caché de Lynceus ({base_resolved}) es el directorio personal; "
            "se niega a borrar nada por seguridad (revisa LYNCEUS_CACHE_DIR)."
        )
    if base_resolved == Path(base_resolved.anchor):
        raise CleanError(
            f"La base de la caché de Lynceus ({base_resolved}) es la raíz del sistema de ficheros; "
            "se niega a borrar nada por seguridad (revisa LYNCEUS_CACHE_DIR)."
        )
    if resolved.name != "build" or resolved.parent != base_resolved:
        raise CleanError(
            f"{resolved} no es la subcarpeta 'build' esperada dentro de la caché de Lynceus; "
            "se niega a borrarla por seguridad."
        )


def ensure_cache_removal_is_safe() -> Path:
    """Pura validación, sin borrar nada: devuelve la subcarpeta `build` de la
    caché de Lynceus (ver `build.default_cache_root`) si es segura, o lanza
    `CleanError` si no. Pensada para comprobarse antes de borrar ninguna
    imagen: en una operación destructiva, toda validación va antes que
    cualquier borrado, no después."""
    cache_dir = default_cache_root()
    _ensure_safe_build_cache_dir(cache_dir)
    return cache_dir


def remove_cache_dir() -> Path | None:
    """Borra la subcarpeta `build` de la caché de Lynceus, tras comprobar
    (de nuevo) que es segura; devuelve la ruta borrada o `None` si no
    existía."""
    cache_dir = ensure_cache_removal_is_safe()
    if not cache_dir.exists():
        return None
    shutil.rmtree(cache_dir)
    return cache_dir
