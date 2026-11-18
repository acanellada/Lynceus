"""Comprueba el workflow .github/workflows/security.yml como YAML (pyyaml ya
es una dependencia del proyecto) sin ejecutarlo: disparadores, permisos, que
el scan de un caso vulnerable a propósito no haga fallar el job, y que
upload-sarif esté fijada por commit SHA y no por una etiqueta movible."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

SECURITY_WORKFLOW_PATH = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "security.yml"

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _load_workflow() -> dict:
    # "on" es palabra reservada en PyYAML 1.1 y se carga como la clave booleana
    # True; lo relevante aquí es el contenido, no el nombre de la clave.
    return yaml.safe_load(SECURITY_WORKFLOW_PATH.read_text())


def _steps():
    workflow = _load_workflow()
    return workflow["jobs"]["scan"]["steps"]


def test_triggers_on_push_to_main_and_manual_dispatch():
    workflow = _load_workflow()
    triggers = workflow[True]
    assert "main" in triggers["push"]["branches"]
    assert "workflow_dispatch" in triggers


def test_permissions_are_least_privilege():
    workflow = _load_workflow()
    assert workflow["permissions"] == {"security-events": "write", "contents": "read"}


def test_checkout_does_not_persist_credentials():
    step = next(s for s in _steps() if s.get("uses", "").startswith("actions/checkout@"))
    assert step["with"]["persist-credentials"] is False


def test_installs_uv_with_hashes():
    step = next(s for s in _steps() if "pip install" in s.get("run", ""))
    assert "--require-hashes" in step["run"]
    assert "sandbox/resolver/requirements.txt" in step["run"]


def test_scans_a_known_vulnerable_benchmark_case():
    step = next(s for s in _steps() if "lynceus scan" in s.get("run", ""))
    assert "benchmark/cases/cmdi-01-vulnerable" in step["run"]
    assert "--classes command_injection" in step["run"]
    assert "--sarif" in step["run"]


def test_vulnerable_scan_does_not_fail_the_job():
    step = next(s for s in _steps() if "lynceus scan" in s.get("run", ""))
    assert step.get("continue-on-error") is True


def test_sarif_upload_always_runs():
    step = next(s for s in _steps() if "upload-sarif" in s.get("uses", ""))
    assert step.get("if") == "always()"


def test_upload_sarif_pinned_by_commit_sha_not_by_tag():
    step = next(s for s in _steps() if "upload-sarif" in s.get("uses", ""))
    action_ref, _, ref = step["uses"].partition("@")
    assert action_ref == "github/codeql-action/upload-sarif"
    assert _SHA_RE.match(ref), f"upload-sarif debe estar fijada por commit SHA, no por etiqueta: {ref!r}"


def test_does_not_add_a_new_third_party_action():
    for step in _steps():
        uses = step.get("uses")
        if uses is None:
            continue
        assert uses.startswith(("actions/", "github/codeql-action/")), f"acción de terceros no esperada: {uses}"
