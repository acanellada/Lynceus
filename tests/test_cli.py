import json
import re
from contextlib import ExitStack
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from lynceus_sec.cli import app
from lynceus_sec.core.metrics import compute_metrics
from lynceus_sec.core.model import Finding, ReproductionCall, VulnClass
from lynceus_sec.validator.bench import CLASS_CONFIG, BenchResult

runner = CliRunner()

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_EMOJI_CHARS = "👁🛡🧪🔍📄✅❌⚠"


@pytest.fixture
def case_dir(tmp_path):
    target = tmp_path / "case"
    target.mkdir()
    (target / "server.py").write_text("# dummy server.py\n")
    return target


def _finding(tool="git_log", parameter="ref", technique="shell_semicolon_bare"):
    return Finding(
        case="x", rule_id=f"cmdi-{technique}", vuln_class=VulnClass.COMMAND_INJECTION, tool=tool,
        severity="critical",
        message=f"Inyección de comandos confirmada en el parámetro '{parameter}' de la tool '{tool}' ({technique})",
        evidence="Canario creado en /tmp/x", validated=True,
        parameter=parameter, technique=technique, payload="; id",
        reproduction=[ReproductionCall(tool=tool, arguments={parameter: "; id"})],
    )


def _patched_validators(cmdi_result=([], []), ptrav_result=([], []), ssrf_result=([], [])):
    stack = ExitStack()
    stack.enter_context(patch("lynceus_sec.validator.cmdi.validate_case", return_value=cmdi_result))
    stack.enter_context(patch("lynceus_sec.validator.ptrav.validate_case", return_value=ptrav_result))
    stack.enter_context(patch("lynceus_sec.validator.ssrf.validate_case", return_value=ssrf_result))
    return stack


# -- exit codes -----------------------------------------------------------

def test_scan_exit_code_0_without_findings(case_dir):
    with _patched_validators():
        result = runner.invoke(app, ["scan", str(case_dir), "--plain"])
    assert result.exit_code == 0


def test_scan_exit_code_1_with_confirmed_findings(case_dir):
    with _patched_validators(cmdi_result=([_finding()], [])):
        result = runner.invoke(app, ["scan", str(case_dir), "--plain"])
    assert result.exit_code == 1


def test_scan_exit_code_2_when_target_is_not_a_directory(tmp_path):
    missing = tmp_path / "does-not-exist"
    result = runner.invoke(app, ["scan", str(missing), "--plain"])
    assert result.exit_code == 2
    assert "no es una carpeta" in result.stdout
    assert "Traceback" not in result.stdout


def test_scan_exit_code_2_when_server_py_is_missing(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    result = runner.invoke(app, ["scan", str(empty), "--plain"])
    assert result.exit_code == 2
    assert "no contiene server.py" in result.stdout
    assert "Traceback" not in result.stdout


def test_scan_exit_code_2_on_unknown_class(case_dir):
    result = runner.invoke(app, ["scan", str(case_dir), "--classes", "not_a_class", "--plain"])
    assert result.exit_code == 2
    assert "Clase desconocida" in result.stdout


def test_scan_exit_code_2_on_runner_error(case_dir):
    from lynceus_sec.validator.runner import RunnerError

    with patch("lynceus_sec.validator.cmdi.validate_case", side_effect=RunnerError("docker no disponible")):
        result = runner.invoke(app, ["scan", str(case_dir), "--classes", "command_injection", "--plain"])
    assert result.exit_code == 2
    assert "docker no disponible" in result.stdout


# -- --classes filtra qué validadores se llaman ---------------------------

def test_scan_classes_option_only_runs_selected_class(case_dir):
    with patch("lynceus_sec.validator.cmdi.validate_case", return_value=([], [])) as cmdi_mock, \
         patch("lynceus_sec.validator.ptrav.validate_case", return_value=([], [])) as ptrav_mock, \
         patch("lynceus_sec.validator.ssrf.validate_case", return_value=([], [])) as ssrf_mock:
        result = runner.invoke(app, ["scan", str(case_dir), "--classes", "command_injection", "--plain"])

    assert result.exit_code == 0
    cmdi_mock.assert_called_once()
    ptrav_mock.assert_not_called()
    ssrf_mock.assert_not_called()


# -- modo plano: sin ANSI ni emoji -----------------------------------------

def test_scan_plain_flag_has_no_ansi_or_emoji(case_dir):
    with _patched_validators(cmdi_result=([_finding()], [{"tool": "x", "parameter": "y", "technique": "z", "detail": "d"}])):
        result = runner.invoke(app, ["scan", str(case_dir), "--plain"])
    assert not _ANSI_RE.search(result.stdout)
    assert not any(ch in result.stdout for ch in _EMOJI_CHARS)


def test_scan_default_non_interactive_output_has_no_ansi_or_emoji(case_dir):
    """CliRunner no es una terminal interactiva: debe caer en modo plano aunque no se pase --plain."""
    with _patched_validators(cmdi_result=([_finding()], [])):
        result = runner.invoke(app, ["scan", str(case_dir)])
    assert not _ANSI_RE.search(result.stdout)
    assert not any(ch in result.stdout for ch in _EMOJI_CHARS)


# -- JSON -------------------------------------------------------------------

def test_scan_json_report_structure(case_dir, tmp_path):
    json_path = tmp_path / "out.json"
    with _patched_validators(cmdi_result=([_finding()], [])):
        result = runner.invoke(
            app, ["scan", str(case_dir), "--plain", "--classes", "command_injection", "--json", str(json_path)],
        )
    assert result.exit_code == 1
    payload = json.loads(json_path.read_text())

    assert payload["schema_version"] == 1
    assert payload["target"] == str(case_dir)
    assert payload["classes"] == ["command_injection"]
    assert payload["summary"]["vulnerabilities_confirmed"] == 1
    assert payload["summary"]["techniques_confirmed"] == 1
    assert payload["summary"]["inconclusive"] == 0
    assert isinstance(payload["summary"]["elapsed_seconds"], float)
    assert len(payload["vulnerabilities"]) == 1
    vuln = payload["vulnerabilities"][0]
    assert vuln["tool"] == "git_log"
    assert vuln["parameter"] == "ref"
    assert vuln["vuln_class"] == "command_injection"
    assert vuln["severity"] == "critical"
    assert vuln["techniques"] == ["shell_semicolon_bare"]
    assert len(vuln["confirmations"]) == 1
    confirmation = vuln["confirmations"][0]
    assert confirmation["technique"] == "shell_semicolon_bare"
    assert confirmation["payload"] == "; id"
    assert confirmation["evidence"] == "Canario creado en /tmp/x"
    assert confirmation["reproduction"] == [{"tool": "git_log", "arguments": {"ref": "; id"}}]
    assert "environment" in payload
    assert payload["environment"]["lynceus_version"]


def test_scan_json_groups_multiple_techniques_into_one_vulnerability(case_dir, tmp_path):
    json_path = tmp_path / "out.json"
    f1 = _finding(technique="shell_semicolon_bare")
    f2 = _finding(technique="shell_and_bare")
    with _patched_validators(cmdi_result=([f1, f2], [])):
        result = runner.invoke(
            app, ["scan", str(case_dir), "--plain", "--classes", "command_injection", "--json", str(json_path)],
        )
    assert result.exit_code == 1
    payload = json.loads(json_path.read_text())

    assert payload["summary"]["vulnerabilities_confirmed"] == 1
    assert payload["summary"]["techniques_confirmed"] == 2
    assert len(payload["vulnerabilities"]) == 1
    assert payload["vulnerabilities"][0]["techniques"] == ["shell_semicolon_bare", "shell_and_bare"]
    assert len(payload["vulnerabilities"][0]["confirmations"]) == 2


def test_scan_json_malicious_tool_name_does_not_merge_attribution(case_dir, tmp_path):
    """Un nombre de tool diseñado para parecer el de otra herramienta no debe
    fusionarse con ella: la agrupación usa `tool` tal cual, no interpretado."""
    json_path = tmp_path / "out.json"
    legit = _finding(tool="read_file", parameter="path")
    spoofed = _finding(tool="read_file' de la tool 'other_tool", parameter="path")
    with _patched_validators(cmdi_result=([legit, spoofed], [])):
        result = runner.invoke(
            app, ["scan", str(case_dir), "--plain", "--classes", "command_injection", "--json", str(json_path)],
        )
    assert result.exit_code == 1
    payload = json.loads(json_path.read_text())

    assert len(payload["vulnerabilities"]) == 2
    tools = {v["tool"] for v in payload["vulnerabilities"]}
    assert tools == {"read_file", "read_file' de la tool 'other_tool"}


def test_scan_html_report_is_written(case_dir, tmp_path):
    report_path = tmp_path / "out.html"
    with _patched_validators():
        result = runner.invoke(
            app, ["scan", str(case_dir), "--plain", "--classes", "command_injection", "--report", str(report_path)],
        )
    assert result.exit_code == 0
    html_text = report_path.read_text()
    assert "Content-Security-Policy" in html_text
    assert "LYNCEUS" in html_text or "L Y N C E U S" in html_text


# -- ayuda --------------------------------------------------------------------

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(text: str) -> str:
    """Quita los códigos ANSI que Typer emite en CI (p. ej. bajo GITHUB_ACTIONS)."""
    return _ANSI_RE.sub("", text)


def test_root_help_lists_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "bench" in result.stdout


def test_scan_help_lists_options():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    output = _strip_ansi(result.stdout)
    for option in ("--classes", "--json", "--report", "--plain"):
        assert option in output


def test_bench_help_lists_options():
    result = runner.invoke(app, ["bench", "--help"])
    assert result.exit_code == 0
    output = _strip_ansi(result.stdout)
    assert "--classes" in output
    assert "--plain" in output


# -- bench --------------------------------------------------------------------

def _empty_bench_result(class_name: str, vuln_class: VulnClass) -> BenchResult:
    metrics = compute_metrics([], {})
    return BenchResult(
        class_name=class_name, vuln_class=vuln_class, case_results=[], all_findings=[], labels={},
        inconclusive_by_case={}, metrics=metrics, missed_due_to_inconclusive=0,
    )


def test_bench_renders_per_class_and_global_metrics_plain():
    def fake_run_class_benchmark(class_name):
        return _empty_bench_result(class_name, CLASS_CONFIG[class_name]["vuln_class"])

    with patch("lynceus_sec.cli.run_class_benchmark", side_effect=fake_run_class_benchmark):
        result = runner.invoke(app, ["bench", "--plain"])

    assert result.exit_code == 0
    assert "Inyección de comandos: tp=0 fp=0 fn=0" in result.stdout
    assert "Path traversal: tp=0 fp=0 fn=0" in result.stdout
    assert "SSRF: tp=0 fp=0 fn=0" in result.stdout
    assert "Global: tp=0 fp=0 fn=0" in result.stdout


def test_bench_unknown_class_exit_code_2():
    result = runner.invoke(app, ["bench", "--classes", "not_a_class", "--plain"])
    assert result.exit_code == 2
