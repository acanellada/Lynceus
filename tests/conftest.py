"""Fixtures compartidas por toda la batería.

`lynceus build` cachea en `~/.cache/lynceus/build` por defecto (ver
`validator.build.default_cache_root`); sin esta fixture, los tests que
ejercitan `run_build` escriben ahí de verdad. La fixture autouse apunta esa
caché a un `tmp_path` por test, y la guarda de sesión falla si, a pesar de
ello, algo llega a escribir en el directorio real del usuario.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REAL_LYNCEUS_CACHE_DIR = Path.home() / ".cache" / "lynceus"


@pytest.fixture(autouse=True)
def _isolated_lynceus_cache_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("LYNCEUS_CACHE_DIR", str(tmp_path / "lynceus-cache"))


def _snapshot(path: Path) -> frozenset[Path]:
    if not path.exists():
        return frozenset()
    return frozenset(path.rglob("*"))


@pytest.fixture(scope="session", autouse=True)
def _guard_real_lynceus_cache_dir_untouched():
    """Ningún test debe escribir en la caché real de `lynceus build`: la
    fixture `_isolated_lynceus_cache_dir` la redirige a `tmp_path`, pero si
    algún código ignora `LYNCEUS_CACHE_DIR` (o un test futuro la fija mal)
    esto lo detecta en vez de dejarlo pasar en silencio."""
    before = _snapshot(REAL_LYNCEUS_CACHE_DIR)
    yield
    after = _snapshot(REAL_LYNCEUS_CACHE_DIR)
    new_entries = after - before
    assert not new_entries, (
        f"La batería ha escrito en la caché real {REAL_LYNCEUS_CACHE_DIR}: "
        f"{sorted(str(p) for p in new_entries)}"
    )
