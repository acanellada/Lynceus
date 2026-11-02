"""`scripts/eval_dynamic.py` es ahora un envoltorio fino sobre
`lynceus_sec.validator.bench`; estos tests comprueban que su salida de texto
no cambió al mover la lógica."""

import runpy
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from lynceus_sec.core.model import Finding, VulnClass
from lynceus_sec.validator.runner import RunnerError

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "eval_dynamic.py"


def _run_script(args: list[str]) -> int:
    old_argv = sys.argv
    sys.argv = ["eval_dynamic.py", *args]
    try:
        with pytest.raises(SystemExit) as exc_info:
            runpy.run_path(str(SCRIPT), run_name="__main__")
        return exc_info.value.code
    finally:
        sys.argv = old_argv


def _fake_validate_case(case_dir, **kwargs):
    name = Path(case_dir).name
    if "vulnerable" in name:
        finding = Finding(
            case=name, rule_id="cmdi-shell_semicolon_bare", vuln_class=VulnClass.COMMAND_INJECTION,
            tool="git_log", severity="high",
            message="Inyección de comandos confirmada en el parámetro 'ref' de la tool 'git_log' "
                    "(shell_semicolon_bare)",
            evidence="payload='; id' canary=/tmp/x", validated=True,
        )
        return [finding], []
    return [], []


def test_wrapper_output_shape_matches_original_script(capsys):
    with patch("lynceus_sec.validator.cmdi.validate_case", side_effect=_fake_validate_case):
        code = _run_script(["--class", "command_injection"])

    out = capsys.readouterr().out
    assert code == 0
    assert "== cmdi-01-fixed ==" in out
    assert "(sin hallazgos confirmados)" in out
    assert "CONFIRMED: git_log (cmdi-shell_semicolon_bare) -> " in out
    assert "== métricas (command_injection, solo casos cmdi-*) ==" in out
    assert "tp=" in out and "fp=" in out and "fn=" in out and "precision=" in out and "recall=" in out
    assert "etiquetas de command_injection sin hallazgo por resultados inconclusos:" in out
    assert "== intentos inconclusos por caso ==" in out


def test_wrapper_defaults_to_command_injection_without_class_flag(capsys):
    with patch("lynceus_sec.validator.cmdi.validate_case", return_value=([], [])):
        code = _run_script([])

    out = capsys.readouterr().out
    assert code == 0
    assert "== métricas (command_injection, solo casos cmdi-*) ==" in out


def test_wrapper_prints_error_and_continues_on_runner_error(capsys):
    def raising(case_dir, **kwargs):
        raise RunnerError("boom")

    with patch("lynceus_sec.validator.cmdi.validate_case", side_effect=raising):
        code = _run_script(["--class", "command_injection"])

    out = capsys.readouterr().out
    assert code == 0
    assert "ERROR ejecutando la validación: boom" in out


def test_wrapper_prints_inconclusive_attempts_by_case(capsys):
    def with_inconclusive(case_dir, **kwargs):
        name = Path(case_dir).name
        if "vulnerable" in name:
            return [], [{"tool": "git_log", "parameter": "ref", "technique": "t", "detail": "d"}]
        return [], []

    with patch("lynceus_sec.validator.cmdi.validate_case", side_effect=with_inconclusive):
        code = _run_script(["--class", "command_injection"])

    out = capsys.readouterr().out
    assert code == 0
    assert "-- cmdi-01-vulnerable --" in out
    assert "tool=git_log parameter=ref technique=t detail=d" in out
