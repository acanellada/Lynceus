"""Comprueba que action.yml es YAML válido, con las entradas, salidas y pasos
esperados (sin ejecutar la action, igual que tests/test_ci_workflow.py para
el workflow de CI). pyyaml ya es una dependencia del proyecto (pyproject.toml)."""

from __future__ import annotations

from pathlib import Path

import yaml

ACTION_PATH = Path(__file__).resolve().parent.parent / "action.yml"


def _load_action() -> dict:
    return yaml.safe_load(ACTION_PATH.read_text())


def test_action_target_input_is_required():
    action = _load_action()
    assert action["inputs"]["target"]["required"] is True


def test_action_optional_inputs_have_defaults():
    action = _load_action()
    for name in ("classes", "entry", "pythonpath", "image", "fs-root"):
        assert action["inputs"][name]["required"] is False

    assert action["inputs"]["sarif-output"]["default"] == "lynceus.sarif"


def test_action_exposes_exit_code_output():
    action = _load_action()
    assert "exit-code" in action["outputs"]


def test_action_is_composite():
    action = _load_action()
    assert action["runs"]["using"] == "composite"


def test_action_builds_sandbox_image():
    action = _load_action()
    runs = " ".join(step.get("run", "") for step in action["runs"]["steps"])
    assert "docker build -t lynceus-sandbox:0.1 sandbox/" in runs


def test_action_syncs_locked_dependencies():
    action = _load_action()
    runs = " ".join(step.get("run", "") for step in action["runs"]["steps"])
    assert "uv sync --locked" in runs


def test_action_installs_uv_with_hashes():
    action = _load_action()
    runs = " ".join(step.get("run", "") for step in action["runs"]["steps"])
    assert "--require-hashes" in runs
    assert "sandbox/resolver/requirements.txt" in runs


def test_action_runs_lynceus_scan():
    action = _load_action()
    runs = " ".join(step.get("run", "") for step in action["runs"]["steps"])
    assert "uv run lynceus scan" in runs
    assert "--sarif" in runs


def test_action_exposes_scan_exit_code_via_github_output():
    action = _load_action()
    runs = " ".join(step.get("run", "") for step in action["runs"]["steps"])
    assert 'echo "exit-code=$code" >> "$GITHUB_OUTPUT"' in runs


def test_action_inputs_are_not_interpolated_directly_in_scan_script():
    """Los valores de las entradas deben llegar al paso de scan por variables
    de entorno, nunca interpolados con ${{ }} dentro del script de shell:
    así una entrada controlada por quien invoca la action no puede inyectar
    comandos."""
    action = _load_action()
    scan_step = next(s for s in action["runs"]["steps"] if s.get("id") == "scan")
    assert "${{" not in scan_step["run"]


def test_action_documents_target_runs_on_the_caller_runner():
    action = _load_action()
    assert "runner" in action["description"].lower()
    assert "confianza" in action["description"].lower()
