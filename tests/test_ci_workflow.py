"""Comprueba el workflow de CI como texto (sin añadir PyYAML como dependencia
nueva solo para parsearlo): la caché de descargas de uv debe existir, usar el
hash de uv.lock como clave, y aparecer antes de `uv sync --locked`."""

from __future__ import annotations

from pathlib import Path

CI_WORKFLOW_PATH = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"


def _ci_workflow_text() -> str:
    return CI_WORKFLOW_PATH.read_text()


def test_ci_workflow_caches_uv_downloads():
    text = _ci_workflow_text()
    assert "actions/cache@" in text


def test_ci_workflow_cache_key_is_based_on_uv_lock_hash():
    text = _ci_workflow_text()
    assert "hashFiles('uv.lock')" in text


def test_ci_workflow_caches_uv_downloads_directory():
    text = _ci_workflow_text()
    assert "~/.cache/uv" in text


def test_ci_workflow_cache_step_runs_before_uv_sync():
    text = _ci_workflow_text()
    cache_index = text.index("actions/cache@")
    sync_index = text.index("uv sync --locked")
    assert cache_index < sync_index


def test_ci_workflow_does_not_add_a_new_third_party_action():
    text = _ci_workflow_text()
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("uses:"):
            assert stripped.startswith("uses: actions/"), f"acción de terceros no esperada: {stripped}"
