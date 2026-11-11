"""Tests de `validator.real_source` sin red: clona y extrae commits de un
repositorio git local (una carpeta con `git init`), nunca de una URL remota."""

import os
import subprocess
import threading
import time
from pathlib import Path

import pytest

from lynceus_sec.validator import real_source

_COMMIT_DATE = "2026-01-15T10:00:00+00:00"


def _git(repo: Path, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env,
    )


def _init_repo_with_commit(path: Path, *, filename: str = "file.txt", content: str = "hello\n") -> str:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q")
    _git(path, "config", "user.email", "lynceus-tests@example.com")
    _git(path, "config", "user.name", "Lynceus Tests")
    (path / filename).write_text(content)
    _git(path, "add", filename)
    env = {**os.environ, "GIT_AUTHOR_DATE": _COMMIT_DATE, "GIT_COMMITTER_DATE": _COMMIT_DATE}
    _git(path, "commit", "-q", "-m", f"add {filename}", env=env)
    return _git(path, "rev-parse", "HEAD").stdout.strip()


@pytest.fixture
def source_repo(tmp_path):
    repo = tmp_path / "source"
    sha = _init_repo_with_commit(repo)
    return repo, sha


def test_clone_repo_once_clones_a_local_repo(tmp_path, source_repo):
    repo, _sha = source_repo
    cache_root = tmp_path / "cache"
    repo_dir = real_source.clone_repo_once(str(repo), cache_root=cache_root)
    assert (repo_dir / ".git").exists()
    assert repo_dir.is_relative_to(real_source.repos_root(cache_root=cache_root))


def test_clone_repo_once_is_idempotent(tmp_path, source_repo):
    repo, _sha = source_repo
    cache_root = tmp_path / "cache"
    first = real_source.clone_repo_once(str(repo), cache_root=cache_root)
    second = real_source.clone_repo_once(str(repo), cache_root=cache_root)
    assert first == second


def test_ensure_worktree_extracts_requested_commit(tmp_path, source_repo):
    repo, sha = source_repo
    cache_root = tmp_path / "cache"
    repo_dir = real_source.clone_repo_once(str(repo), cache_root=cache_root)
    workdir = tmp_path / "work"

    result = real_source.ensure_worktree(repo_dir, sha, workdir)

    assert result == workdir
    assert (workdir / "file.txt").read_text() == "hello\n"
    assert real_source.checked_out_commit(workdir) == sha


def test_ensure_worktree_reuses_an_existing_matching_workdir(tmp_path, source_repo):
    repo, sha = source_repo
    cache_root = tmp_path / "cache"
    repo_dir = real_source.clone_repo_once(str(repo), cache_root=cache_root)
    workdir = tmp_path / "work"

    real_source.ensure_worktree(repo_dir, sha, workdir)
    # Segunda llamada, mismo commit: no debe fallar ni recrear el worktree.
    result = real_source.ensure_worktree(repo_dir, sha, workdir)

    assert result == workdir
    assert real_source.checked_out_commit(workdir) == sha


def test_ensure_worktree_rejects_a_workdir_with_a_different_commit_already_extracted(tmp_path, source_repo):
    repo, first_sha = source_repo
    second_sha = _init_repo_with_commit(repo, filename="other.txt", content="bye\n")
    cache_root = tmp_path / "cache"
    repo_dir = real_source.clone_repo_once(str(repo), cache_root=cache_root)
    workdir = tmp_path / "work"

    real_source.ensure_worktree(repo_dir, first_sha, workdir)

    with pytest.raises(real_source.RealSourceError, match="no coincide|no, el commit pedido|ya existe"):
        real_source.ensure_worktree(repo_dir, second_sha, workdir)


def test_commit_date_matches_the_committed_date(tmp_path, source_repo):
    repo, sha = source_repo
    cache_root = tmp_path / "cache"
    repo_dir = real_source.clone_repo_once(str(repo), cache_root=cache_root)

    assert real_source.commit_date(repo_dir, sha) == "2026-01-15"


def test_prepare_version_source_clones_and_extracts_in_one_call(tmp_path, source_repo):
    repo, sha = source_repo
    cache_root = tmp_path / "cache"

    workdir = real_source.prepare_version_source("cve-test", "vulnerable", str(repo), sha, cache_root=cache_root)

    assert workdir == real_source.version_workdir("cve-test", "vulnerable", cache_root=cache_root)
    assert real_source.checked_out_commit(workdir) == sha


def test_hooks_are_disabled_when_extracting_a_worktree(tmp_path, source_repo):
    """Un hook `post-checkout` en el clon no debe ejecutarse al extraer un
    commit: comprueba que `-c core.hooksPath=/dev/null` surte efecto."""
    repo, sha = source_repo
    cache_root = tmp_path / "cache"
    repo_dir = real_source.clone_repo_once(str(repo), cache_root=cache_root)

    marker = tmp_path / "hook-ran"
    hooks_dir = repo_dir / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "post-checkout"
    hook_path.write_text(f"#!/bin/sh\ntouch {marker}\n")
    hook_path.chmod(0o755)

    workdir = tmp_path / "work"
    real_source.ensure_worktree(repo_dir, sha, workdir)

    assert not marker.exists()


def test_concurrent_clone_of_same_repo_only_clones_once(tmp_path, source_repo, monkeypatch):
    """Dos versiones del mismo manifiesto, con --jobs > 1, llaman a
    `clone_repo_once` casi a la vez: el cerrojo por repositorio debe
    serializarlas, de modo que solo una de ellas llegue a ejecutar `git
    clone` (la segunda ve ya un clon válido y no hace nada más)."""
    repo, _sha = source_repo
    cache_root = tmp_path / "cache"

    clone_calls: list[list[str]] = []
    original_run_git = real_source._run_git

    def slow_run_git(args, *, cwd=None, step):
        if "clone" in args:
            clone_calls.append(args)
            time.sleep(0.1)  # ensancha la ventana de carrera si el cerrojo no funcionara
        return original_run_git(args, cwd=cwd, step=step)

    monkeypatch.setattr(real_source, "_run_git", slow_run_git)

    results: list[Path] = []
    errors: list[Exception] = []

    def worker() -> None:
        try:
            results.append(real_source.clone_repo_once(str(repo), cache_root=cache_root))
        except Exception as exc:  # noqa: BLE001 - se quiere capturar cualquier fallo del hilo
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(clone_calls) == 1
    assert len({str(path) for path in results}) == 1


def test_half_finished_clone_is_removed_and_recloned(tmp_path, source_repo):
    """Una carpeta de caché sin `.git` (de un clonado interrumpido en una
    ejecución anterior) no es un clon reutilizable: se borra y se vuelve a
    clonar en vez de fallar."""
    repo, sha = source_repo
    cache_root = tmp_path / "cache"
    repo_dir = real_source.repo_cache_dir(str(repo), cache_root=cache_root)
    repo_dir.mkdir(parents=True)
    (repo_dir / "leftover.txt").write_text("de un clonado interrumpido\n")

    result = real_source.clone_repo_once(str(repo), cache_root=cache_root)

    assert result == repo_dir
    assert (repo_dir / ".git").exists()
    workdir = real_source.ensure_worktree(repo_dir, sha, tmp_path / "work")
    assert real_source.checked_out_commit(workdir) == sha


def test_clone_with_mismatched_remote_is_removed_and_recloned(tmp_path, source_repo):
    """Una carpeta de caché que sí es un repositorio git válido, pero cuyo
    remoto `origin` no coincide con el `repo` del manifiesto, tampoco es
    reutilizable: se borra y se clona el repositorio correcto."""
    repo, _sha = source_repo
    cache_root = tmp_path / "cache"
    repo_dir = real_source.repo_cache_dir(str(repo), cache_root=cache_root)
    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", "-q", str(repo), str(repo_dir)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo_dir), "remote", "set-url", "origin", "https://example.com/wrong.git"],
        check=True, capture_output=True,
    )

    result = real_source.clone_repo_once(str(repo), cache_root=cache_root)

    assert result == repo_dir
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), "remote", "get-url", "origin"], check=True, capture_output=True, text=True,
    )
    assert proc.stdout.strip() == str(repo)


def test_repo_cache_dir_is_deterministic_per_url(tmp_path):
    cache_root = tmp_path / "cache"
    first = real_source.repo_cache_dir("https://example.com/a.git", cache_root=cache_root)
    second = real_source.repo_cache_dir("https://example.com/a.git", cache_root=cache_root)
    other = real_source.repo_cache_dir("https://example.com/b.git", cache_root=cache_root)
    assert first == second
    assert first != other
