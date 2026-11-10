"""Reparto de trabajo en paralelo entre contenedores Docker.

Un único `ParallelContext` por invocación de `scan`/`bench` reúne tres piezas,
todas de tamaño `jobs`, para que nunca haya más de `jobs` unidades de trabajo
"en marcha" en ningún sentido:

- `pool`: el único sitio por el que pasa cualquier llamada que arranque o
  ejecute un contenedor o una red (descubrimiento, validación, comprobación
  de aislamiento, creación de red, arranque de receptor). Repartir los
  intentos de un caso entre varios contenedores y ejecutar casos/clases
  distintos a la vez comparten este mismo pool: nunca se crea uno aparte por
  clase o por caso.
- `semaphore`: lo adquiere cada coordinador de caso/clase antes de crear
  nada propio (red, receptor) y lo libera al terminar (con éxito, error o
  interrupción). Acota cuántos casos pueden tener su propia red y su propio
  receptor vivos a la vez, con independencia de cuántos hilos coordinadores
  haya arrancado el nivel de arriba.
- `active`: registro de nombres de contenedor y de red en marcha ahora
  mismo. No sustituye la limpieza propia de cada caso (que sigue matando sus
  contenedores y borrando su red en su propio `finally`, igual que con
  `--jobs 1`); es la red de seguridad para lo que esa limpieza local no
  puede alcanzar: contenedores de OTROS hilos que todavía no han notado el
  fallo cuando se interrumpe la ejecución.

Destruir (matar un contenedor, borrar una red) nunca pasa por `pool`: tiene
que ocurrir de inmediato, no en cola detrás de otro trabajo.
"""

from __future__ import annotations

import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import TypeVar

MIN_JOBS = 1
MAX_JOBS = 16

T = TypeVar("T")


class JobsError(ValueError):
    pass


def validate_jobs(value: int) -> int:
    if not (MIN_JOBS <= value <= MAX_JOBS):
        raise JobsError(f"--jobs debe estar entre {MIN_JOBS} y {MAX_JOBS} (recibido {value}).")
    return value


def docker_cpu_count(*, timeout: float = 5.0) -> int | None:
    """CPUs que ve el daemon Docker (`docker info`); `None` si no se puede saber."""
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.NCPU}}"],
            check=False, capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        return int(proc.stdout.strip())
    except ValueError:
        return None


def partition(items: list[T], parts: int) -> list[list[T]]:
    """Reparte `items` en como mucho `parts` trozos contiguos, sin reordenar.

    Determinista: los mismos `items`/`parts` siempre producen el mismo
    reparto, con independencia de en qué orden terminen luego los trozos.
    """
    if not items or parts <= 1:
        return [items] if items else []
    parts = min(parts, len(items))
    base, extra = divmod(len(items), parts)
    chunks: list[list[T]] = []
    start = 0
    for i in range(parts):
        size = base + (1 if i < extra else 0)
        chunks.append(items[start:start + size])
        start += size
    return chunks


class ActiveSet:
    """Nombres de contenedor y de red en marcha ahora mismo, en toda la
    ejecución (no solo dentro de una llamada a `pool`): quien crea una red o
    arranca un receptor lo registra aquí y lo retira cuando lo destruye."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._containers: set[str] = set()
        self._networks: set[str] = set()

    def add_container(self, name: str) -> None:
        with self._lock:
            self._containers.add(name)

    def discard_container(self, name: str) -> None:
        with self._lock:
            self._containers.discard(name)

    def add_network(self, name: str) -> None:
        with self._lock:
            self._networks.add(name)

    def discard_network(self, name: str) -> None:
        with self._lock:
            self._networks.discard(name)

    def kill_and_clear(self) -> None:
        """Mata todo contenedor registrado y borra toda red registrada;
        mejor esfuerzo, como `kill_container`/`remove_network`. Import
        diferido para no crear un ciclo con `runner` (que importa este
        módulo para `partition` y `ParallelContext`)."""
        from lynceus_sec.validator.runner import kill_container, remove_network

        with self._lock:
            containers = list(self._containers)
            networks = list(self._networks)
            self._containers.clear()
            self._networks.clear()
        for name in containers:
            kill_container(name)
        for name in networks:
            remove_network(name)


@dataclass
class ParallelContext:
    """Estado compartido de una ejecución en paralelo (`scan`/`bench` con
    `--jobs` > 1): un único pool de tamaño `jobs`, un semáforo del mismo
    tamaño para los coordinadores de caso/clase y el registro de limpieza."""

    pool: ThreadPoolExecutor
    semaphore: threading.Semaphore
    active: ActiveSet = field(default_factory=ActiveSet)

    @classmethod
    def create(cls, jobs: int) -> ParallelContext:
        return cls(pool=ThreadPoolExecutor(max_workers=jobs), semaphore=threading.Semaphore(jobs))

    def shutdown(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=True)
