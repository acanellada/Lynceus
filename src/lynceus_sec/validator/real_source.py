"""Obtiene el código fuente de los servidores reales (`benchmark/real/*.toml`):
clona cada repositorio una sola vez en la caché de Lynceus y extrae cada
commit pedido en su propio directorio de trabajo (`git worktree`), sin hooks
ni submódulos.

Caché bajo `build.cache_base_dir() / "real"` (respeta `LYNCEUS_CACHE_DIR`,
igual que la caché de `lynceus build`):

- `repos/<hash>`: clon único de cada repositorio (`--filter=blob:none`: solo
  los blobs que de verdad se llegan a mirar, nunca el historial completo del
  repositorio; pensado para monorepos grandes como `modelcontextprotocol/servers`,
  de los que un manifiesto solo necesita un `subdir`).
- `worktrees/<manifest_id>/<label>`: un `git worktree` por versión, en el
  commit exacto del manifiesto.

Los hooks se desactivan en cada llamada a git sobre estos repos
(`-c core.hooksPath=/dev/null`, nunca en la configuración global del usuario)
y los submódulos nunca se inicializan (ni `--recurse-submodules` al clonar ni
ningún `git submodule` después).

Varias versiones de un mismo manifiesto (o de manifiestos distintos) pueden
compartir repositorio, y `lynceus bench --suite real --jobs N` las valida en
paralelo: todo lo que escribe en el clon compartido (clonar, `git fetch`,
`git worktree add`) pasa por un cerrojo por repositorio (`_lock_for_repo`),
nunca por el pool de contenedores de `validator.parallel` (esto es disco, no
Docker). Un `git worktree add` no vacía ese cerrojo a medias: con `jobs`
hilos coordinadores, nunca hay dos procesos git tocando el mismo clon a la
vez, aunque sí puede haber varios construyendo/escaneando a la vez una vez
que cada uno ya tiene su propio directorio de trabajo.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import threading
from pathlib import Path

from lynceus_sec.validator.build import cache_base_dir

_HOOKS_DISABLED = ["-c", "core.hooksPath=/dev/null"]
_GIT_TIMEOUT = 300.0

# Un `threading.RLock` por repositorio (clave: su carpeta de caché, ya
# determinista por `repo_cache_dir`), creado bajo `_locks_guard` para que
# crear la entrada del diccionario no sea en sí mismo una carrera. Reentrante
# porque `ensure_worktree` llama a `ensure_commit_fetched`, que adquiere el
# mismo cerrojo: con un `Lock` normal, eso bloquearía al propio hilo.
_repo_locks: dict[Path, threading.RLock] = {}
_locks_guard = threading.Lock()


def _lock_for_repo(repo_dir: Path) -> threading.RLock:
    with _locks_guard:
        lock = _repo_locks.get(repo_dir)
        if lock is None:
            lock = threading.RLock()
            _repo_locks[repo_dir] = lock
        return lock


class RealSourceError(RuntimeError):
    pass


def real_cache_root(*, cache_root: Path | None = None) -> Path:
    base = cache_root if cache_root is not None else cache_base_dir()
    return Path(base) / "real"


def repos_root(*, cache_root: Path | None = None) -> Path:
    return real_cache_root(cache_root=cache_root) / "repos"


def worktrees_root(*, cache_root: Path | None = None) -> Path:
    return real_cache_root(cache_root=cache_root) / "worktrees"


def repo_cache_dir(repo_url: str, *, cache_root: Path | None = None) -> Path:
    """Carpeta determinista del clon único de `repo_url`: mismo repositorio,
    misma carpeta, con independencia de cuántos manifiestos lo usen."""
    digest = hashlib.sha256(repo_url.encode()).hexdigest()[:16]
    return repos_root(cache_root=cache_root) / digest


def version_workdir(manifest_id: str, label: str, *, cache_root: Path | None = None) -> Path:
    return worktrees_root(cache_root=cache_root) / manifest_id / label


def _run_git(args: list[str], *, cwd: Path | None = None, step: str) -> subprocess.CompletedProcess:
    cmd = ["git", *args]
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, check=False, capture_output=True, text=True, timeout=_GIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise RealSourceError(f"{step} no terminó en {_GIT_TIMEOUT}s") from exc
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"código de salida {proc.returncode}"
        raise RealSourceError(f"{step} falló: {detail}")
    return proc


def _is_valid_existing_clone(repo_dir: Path, repo_url: str) -> bool:
    """Un clon reutilizable: existe, es un repositorio git válido (no uno a
    medias, p. ej. de una ejecución interrumpida) y su remoto `origin` es
    exactamente `repo_url` (si el manifiesto cambió de repositorio entre
    ejecuciones, la carpeta de caché antigua no vale, aunque siga ahí)."""
    if not (repo_dir / ".git").exists():
        return False
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), "remote", "get-url", "origin"],
        check=False, capture_output=True, text=True,
    )
    return proc.returncode == 0 and proc.stdout.strip() == repo_url


def clone_repo_once(repo_url: str, *, cache_root: Path | None = None) -> Path:
    """Clona `repo_url` en su carpeta de caché si no existe ya; si ya existe
    (de una ejecución anterior), la reutiliza tal cual, sin volver a clonar.
    Si esa carpeta existe pero no es un clon válido de `repo_url` (a medias,
    o el remoto de otro repositorio), la borra y clona desde cero. Serializado
    por repositorio: con varias versiones del mismo manifiesto en paralelo
    (`--jobs` > 1), solo una llega a clonar."""
    repo_dir = repo_cache_dir(repo_url, cache_root=cache_root)
    with _lock_for_repo(repo_dir):
        if _is_valid_existing_clone(repo_dir, repo_url):
            return repo_dir
        if repo_dir.exists():
            shutil.rmtree(repo_dir)

        repo_dir.parent.mkdir(parents=True, exist_ok=True)
        _run_git(
            [
                *_HOOKS_DISABLED,
                "clone",
                "--no-recurse-submodules",
                "--filter=blob:none",
                repo_url,
                str(repo_dir),
            ],
            step=f"Clonar {repo_url}",
        )
        return repo_dir


def ensure_commit_fetched(repo_dir: Path, commit: str) -> None:
    """Trae `commit` si el clon (de la rama por defecto) no lo tenía ya: un
    `fetch` superficial de ese SHA exacto, nunca el historial completo. Falla
    con un error claro si el remoto no permite pedir ese commit (algunos
    servidores git, a diferencia de GitHub, no lo permiten). Serializado por
    repositorio, igual que `clone_repo_once`: dos versiones pidiendo commits
    distintos del mismo repo nunca hacen `fetch` a la vez sobre él."""
    with _lock_for_repo(repo_dir):
        proc = subprocess.run(
            ["git", "-C", str(repo_dir), "cat-file", "-e", f"{commit}^{{commit}}"],
            check=False, capture_output=True, text=True,
        )
        if proc.returncode == 0:
            return
        _run_git(
            [*_HOOKS_DISABLED, "-C", str(repo_dir), "fetch", "--depth=1", "origin", commit],
            step=f"Obtener el commit {commit} de {repo_dir}",
        )


def checked_out_commit(workdir: Path) -> str:
    proc = _run_git(["-C", str(workdir), "rev-parse", "HEAD"], step=f"Leer el commit extraído en {workdir}")
    return proc.stdout.strip()


def ensure_worktree(repo_dir: Path, commit: str, workdir: Path) -> Path:
    """Extrae `commit` en `workdir` (un `git worktree` nuevo, detached) si no
    existe ya; si ya existe (de una ejecución anterior), comprueba que el
    commit extraído es exactamente el pedido antes de reutilizarlo.
    Serializado por repositorio (`_lock_for_repo`, reentrante): dos versiones
    del mismo manifiesto, cada una con su propio `workdir`, nunca hacen
    `git worktree add` a la vez sobre el mismo `repo_dir`."""
    with _lock_for_repo(repo_dir):
        if workdir.exists():
            actual = checked_out_commit(workdir)
            if actual != commit:
                raise RealSourceError(
                    f"{workdir} ya existe pero tiene extraído {actual!r}, no el commit pedido {commit!r}; "
                    "bórralo si quieres que Lynceus lo recree."
                )
            return workdir

        ensure_commit_fetched(repo_dir, commit)
        workdir.parent.mkdir(parents=True, exist_ok=True)
        _run_git(
            [*_HOOKS_DISABLED, "-C", str(repo_dir), "worktree", "add", "--detach", str(workdir), commit],
            step=f"Extraer el commit {commit} en {workdir}",
        )

        actual = checked_out_commit(workdir)
        if actual != commit:
            raise RealSourceError(
                f"El commit extraído en {workdir} ({actual!r}) no coincide con el pedido ({commit!r})"
            )
        return workdir


def commit_date(repo_dir: Path, commit: str) -> str:
    """Fecha (AAAA-MM-DD) del commit, en la zona horaria del propio commit:
    usada como `resolve_date` por defecto cuando una versión no la indica."""
    ensure_commit_fetched(repo_dir, commit)
    proc = _run_git(
        ["-C", str(repo_dir), "show", "-s", "--format=%cI", commit],
        step=f"Leer la fecha del commit {commit}",
    )
    iso = proc.stdout.strip()
    if len(iso) < 10:
        raise RealSourceError(f"Fecha de commit inesperada para {commit}: {iso!r}")
    return iso[:10]


def prepare_version_source(
    manifest_id: str,
    label: str,
    repo_url: str,
    commit: str,
    *,
    cache_root: Path | None = None,
) -> Path:
    """Clona (si hace falta) y extrae `commit` en su propio directorio de
    trabajo; devuelve esa ruta. Operación completa para una versión de un
    manifiesto: lo único que necesita `real_bench` para seguir con `build`/`scan`."""
    repo_dir = clone_repo_once(repo_url, cache_root=cache_root)
    workdir = version_workdir(manifest_id, label, cache_root=cache_root)
    return ensure_worktree(repo_dir, commit, workdir)
