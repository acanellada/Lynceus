import json
import re
import subprocess
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from lynceus_sec.cli import app
from lynceus_sec.core.metrics import compute_metrics
from lynceus_sec.core.model import Finding, ReproductionCall, VulnClass
from lynceus_sec.validator import build as build_mod
from lynceus_sec.validator import clean as clean_mod
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
    assert "no contiene el punto de entrada" in result.stdout
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


# -- --fs-root --------------------------------------------------------------

def test_scan_fs_root_rejects_relative_path(case_dir):
    result = runner.invoke(app, ["scan", str(case_dir), "--fs-root", "tmp/relativo", "--plain"])
    assert result.exit_code == 2
    assert "--fs-root" in result.stdout


def test_scan_fs_root_rejects_path_outside_tmp(case_dir):
    result = runner.invoke(app, ["scan", str(case_dir), "--fs-root", "/var/lynceus-root", "--plain"])
    assert result.exit_code == 2
    assert "/tmp" in result.stdout


def test_scan_fs_root_rejects_tmp_itself(case_dir):
    result = runner.invoke(app, ["scan", str(case_dir), "--fs-root", "/tmp", "--plain"])
    assert result.exit_code == 2


def test_scan_fs_root_rejects_dotdot_escape(case_dir):
    result = runner.invoke(app, ["scan", str(case_dir), "--fs-root", "/tmp/../etc", "--plain"])
    assert result.exit_code == 2


def test_scan_fs_root_valid_value_is_passed_to_ptrav_validate_case(case_dir):
    with patch("lynceus_sec.validator.cmdi.validate_case", return_value=([], [])), \
         patch("lynceus_sec.validator.ptrav.validate_case", return_value=([], [])) as ptrav_mock, \
         patch("lynceus_sec.validator.ssrf.validate_case", return_value=([], [])):
        result = runner.invoke(
            app,
            ["scan", str(case_dir), "--classes", "path_traversal", "--fs-root", "/tmp/mi-limite", "--plain"],
        )

    assert result.exit_code == 0
    ptrav_mock.assert_called_once_with(case_dir, fs_root="/tmp/mi-limite", entry="server.py", pythonpath=[])
    assert "/tmp/mi-limite" in result.stdout


def test_scan_fs_root_defaults_to_lynceus_root(case_dir):
    with patch("lynceus_sec.validator.cmdi.validate_case", return_value=([], [])), \
         patch("lynceus_sec.validator.ptrav.validate_case", return_value=([], [])) as ptrav_mock, \
         patch("lynceus_sec.validator.ssrf.validate_case", return_value=([], [])):
        result = runner.invoke(app, ["scan", str(case_dir), "--classes", "path_traversal", "--plain"])

    assert result.exit_code == 0
    ptrav_mock.assert_called_once_with(case_dir, fs_root="/tmp/lynceus-root", entry="server.py", pythonpath=[])


# -- --entry / --pythonpath --------------------------------------------------

def test_scan_entry_rejects_path_outside_target(case_dir):
    result = runner.invoke(app, ["scan", str(case_dir), "--entry", "../server.py", "--plain"])
    assert result.exit_code == 2
    assert "--entry" in result.stdout


def test_scan_entry_rejects_absolute_path(case_dir):
    result = runner.invoke(app, ["scan", str(case_dir), "--entry", "/etc/passwd", "--plain"])
    assert result.exit_code == 2
    assert "--entry" in result.stdout


def test_scan_entry_rejects_non_python_file(case_dir):
    (case_dir / "notes.txt").write_text("hola")
    result = runner.invoke(app, ["scan", str(case_dir), "--entry", "notes.txt", "--plain"])
    assert result.exit_code == 2
    assert "--entry" in result.stdout
    assert ".py" in result.stdout


def test_scan_entry_rejects_missing_file(case_dir):
    result = runner.invoke(app, ["scan", str(case_dir), "--entry", "missing.py", "--plain"])
    assert result.exit_code == 2
    assert "no contiene el punto de entrada" in result.stdout


def test_scan_pythonpath_rejects_path_outside_target(case_dir):
    result = runner.invoke(app, ["scan", str(case_dir), "--pythonpath", "../lib", "--plain"])
    assert result.exit_code == 2
    assert "--pythonpath" in result.stdout


def test_scan_pythonpath_rejects_absolute_path(case_dir):
    result = runner.invoke(app, ["scan", str(case_dir), "--pythonpath", "/usr/lib", "--plain"])
    assert result.exit_code == 2
    assert "--pythonpath" in result.stdout


def test_scan_pythonpath_rejects_missing_directory(case_dir):
    result = runner.invoke(app, ["scan", str(case_dir), "--pythonpath", "lib", "--plain"])
    assert result.exit_code == 2
    assert "no es una carpeta" in result.stdout


def test_scan_entry_and_pythonpath_are_forwarded_to_all_validators(case_dir):
    (case_dir / "app").mkdir()
    (case_dir / "app" / "main.py").write_text("# entry\n")
    (case_dir / "lib").mkdir()
    with patch("lynceus_sec.validator.cmdi.validate_case", return_value=([], [], [])) as cmdi_mock, \
         patch("lynceus_sec.validator.ptrav.validate_case", return_value=([], [], [])) as ptrav_mock, \
         patch("lynceus_sec.validator.ssrf.validate_case", return_value=([], [])) as ssrf_mock:
        result = runner.invoke(
            app,
            ["scan", str(case_dir), "--entry", "app/main.py", "--pythonpath", "lib", "--plain"],
        )

    assert result.exit_code == 0
    cmdi_mock.assert_called_once_with(case_dir, entry="app/main.py", pythonpath=["lib"])
    ssrf_mock.assert_called_once_with(case_dir, entry="app/main.py", pythonpath=["lib"])
    ptrav_mock.assert_called_once_with(
        case_dir, fs_root="/tmp/lynceus-root", entry="app/main.py", pythonpath=["lib"]
    )


# -- --image -----------------------------------------------------------------

def test_scan_image_rejects_bad_format(case_dir):
    result = runner.invoke(app, ["scan", str(case_dir), "--image", "not-an-image", "--plain"])
    assert result.exit_code == 2
    assert "--image" in result.stdout


def test_scan_image_rejects_wrong_tag_length(case_dir):
    result = runner.invoke(app, ["scan", str(case_dir), "--image", "lynceus-target:abc123", "--plain"])
    assert result.exit_code == 2
    assert "--image" in result.stdout


def test_scan_image_rejects_uppercase_hex(case_dir):
    result = runner.invoke(app, ["scan", str(case_dir), "--image", "lynceus-target:ABC123DEF456", "--plain"])
    assert result.exit_code == 2
    assert "--image" in result.stdout


def test_scan_image_rejects_well_formed_tag_that_does_not_exist_locally(case_dir):
    with patch("lynceus_sec.cli._docker_responding", return_value=True), \
         patch("lynceus_sec.cli._image_exists", return_value=False) as image_exists_mock:
        result = runner.invoke(app, ["scan", str(case_dir), "--image", "lynceus-target:abc123def456", "--plain"])
    assert result.exit_code == 2
    assert "no existe en local" in result.stdout
    image_exists_mock.assert_called_once_with("lynceus-target:abc123def456")


def test_scan_image_reports_docker_not_responding_distinctly_from_missing_image(case_dir):
    """Con Docker en pausa, no debe decir que la imagen no existe (sería
    engañoso): un error distinto, y no debe ni llegar a comprobar la imagen."""
    with patch("lynceus_sec.cli._docker_responding", return_value=False), \
         patch("lynceus_sec.cli._image_exists") as image_exists_mock:
        result = runner.invoke(app, ["scan", str(case_dir), "--image", "lynceus-target:abc123def456", "--plain"])
    assert result.exit_code == 2
    assert "Docker no responde" in result.stdout
    assert "no existe en local" not in result.stdout
    image_exists_mock.assert_not_called()


def test_scan_image_valid_is_forwarded_to_validators_with_fixed_server_python(case_dir):
    from lynceus_sec.validator.runner import TARGET_PYTHON

    with patch("lynceus_sec.cli._docker_responding", return_value=True), \
         patch("lynceus_sec.cli._image_exists", return_value=True), \
         patch("lynceus_sec.validator.cmdi.validate_case", return_value=([], [], [])) as cmdi_mock, \
         patch("lynceus_sec.validator.ptrav.validate_case", return_value=([], [], [])) as ptrav_mock, \
         patch("lynceus_sec.validator.ssrf.validate_case", return_value=([], [])) as ssrf_mock:
        result = runner.invoke(
            app, ["scan", str(case_dir), "--image", "lynceus-target:abc123def456", "--plain"],
        )

    assert result.exit_code == 0
    cmdi_mock.assert_called_once_with(
        case_dir, entry="server.py", pythonpath=[],
        image="lynceus-target:abc123def456", server_python=TARGET_PYTHON,
    )
    ssrf_mock.assert_called_once_with(
        case_dir, entry="server.py", pythonpath=[],
        image="lynceus-target:abc123def456", server_python=TARGET_PYTHON,
    )
    ptrav_mock.assert_called_once_with(
        case_dir, fs_root="/tmp/lynceus-root", entry="server.py", pythonpath=[],
        image="lynceus-target:abc123def456", server_python=TARGET_PYTHON,
    )
    assert "lynceus-target:abc123def456" in result.stdout


def test_scan_without_image_does_not_forward_image_kwargs(case_dir):
    """Sin --image, las llamadas a los validadores no llevan `image` ni
    `server_python`: el comportamiento es idéntico al de antes de --image."""
    with patch("lynceus_sec.validator.cmdi.validate_case", return_value=([], [])) as cmdi_mock, \
         patch("lynceus_sec.validator.ptrav.validate_case", return_value=([], [])) as ptrav_mock, \
         patch("lynceus_sec.validator.ssrf.validate_case", return_value=([], [])) as ssrf_mock:
        result = runner.invoke(app, ["scan", str(case_dir), "--classes", "command_injection", "--plain"])

    assert result.exit_code == 0
    cmdi_mock.assert_called_once_with(case_dir, entry="server.py", pythonpath=[])
    ptrav_mock.assert_not_called()
    ssrf_mock.assert_not_called()


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

    assert payload["schema_version"] == 2
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
    assert payload["environment"]["target_image"] == payload["environment"]["sandbox_image"]


def test_scan_json_report_includes_the_target_image_used_with_image_flag(case_dir, tmp_path):
    json_path = tmp_path / "out.json"
    with patch("lynceus_sec.cli._docker_responding", return_value=True), \
         patch("lynceus_sec.cli._image_exists", return_value=True), \
         _patched_validators(cmdi_result=([], [], [])):
        result = runner.invoke(
            app,
            [
                "scan", str(case_dir), "--plain", "--classes", "command_injection",
                "--image", "lynceus-target:abc123def456", "--json", str(json_path),
            ],
        )
    assert result.exit_code == 0
    payload = json.loads(json_path.read_text())
    assert payload["environment"]["target_image"] == "lynceus-target:abc123def456"


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


def test_scan_json_includes_fs_root_and_positive_controls_without_affecting_classification(case_dir, tmp_path):
    json_path = tmp_path / "out.json"
    positive_control = {"tool": "read_doc", "parameter": "name", "status": "confirmed"}
    ptrav_result = ([], [], [positive_control])
    with _patched_validators(ptrav_result=ptrav_result):
        result = runner.invoke(
            app,
            [
                "scan", str(case_dir), "--plain", "--classes", "path_traversal",
                "--fs-root", "/tmp/mi-limite", "--json", str(json_path),
            ],
        )
    assert result.exit_code == 0
    payload = json.loads(json_path.read_text())

    assert payload["fs_root"] == "/tmp/mi-limite"
    assert payload["summary"]["vulnerabilities_confirmed"] == 0
    assert payload["positive_controls"]["path_traversal"] == [positive_control]


def _capability(tool="run_shell", parameter="command"):
    return {
        "tool": tool,
        "parameter": parameter,
        "probe": {
            "technique": "capability_probe",
            "payload": "touch /tmp/lynceus-canary-probe",
            "evidence": "Canario creado en /tmp/lynceus-canary-probe",
            "reproduction": [ReproductionCall(tool=tool, arguments={parameter: "touch /tmp/lynceus-canary-probe"})],
        },
        "confirmations": [
            {
                "technique": "shell_semicolon_bare",
                "payload": "; touch /tmp/lynceus-canary-inj",
                "evidence": "Canario creado en /tmp/lynceus-canary-inj",
                "reproduction": [
                    ReproductionCall(tool=tool, arguments={parameter: "; touch /tmp/lynceus-canary-inj"})
                ],
            }
        ],
    }


def test_scan_json_includes_capabilities_without_affecting_classification(case_dir, tmp_path):
    json_path = tmp_path / "out.json"
    with _patched_validators(cmdi_result=([], [], [_capability()])):
        result = runner.invoke(
            app, ["scan", str(case_dir), "--plain", "--classes", "command_injection", "--json", str(json_path)],
        )
    assert result.exit_code == 0
    payload = json.loads(json_path.read_text())

    assert payload["schema_version"] == 2
    assert payload["summary"]["vulnerabilities_confirmed"] == 0
    assert payload["summary"]["techniques_confirmed"] == 0
    cap = payload["capabilities"]["command_injection"][0]
    assert cap["tool"] == "run_shell"
    assert cap["probe"]["payload"] == "touch /tmp/lynceus-canary-probe"
    assert cap["confirmations"][0]["technique"] == "shell_semicolon_bare"
    assert "capabilities_note" in payload


def test_scan_plain_shows_capability_section_and_explanation(case_dir):
    with _patched_validators(cmdi_result=([], [], [_capability()])):
        result = runner.invoke(app, ["scan", str(case_dir), "--plain", "--classes", "command_injection"])

    assert result.exit_code == 0
    assert "capacidad detectada" in result.stdout
    assert "No es un fallo de implementación" in result.stdout


def test_scan_json_includes_bypassable_filter_fields(case_dir, tmp_path):
    json_path = tmp_path / "out.json"
    capability = _capability()
    capability["bypassable_filter"] = True
    capability["blocked_techniques"] = ["shell_pipe_bare"]
    with _patched_validators(cmdi_result=([], [], [capability])):
        result = runner.invoke(
            app, ["scan", str(case_dir), "--plain", "--classes", "command_injection", "--json", str(json_path)],
        )
    assert result.exit_code == 0
    payload = json.loads(json_path.read_text())

    cap = payload["capabilities"]["command_injection"][0]
    assert cap["bypassable_filter"] is True
    assert cap["blocked_techniques"] == ["shell_pipe_bare"]
    assert payload["schema_version"] == 2


def test_scan_json_capability_defaults_bypassable_filter_false_when_absent(case_dir, tmp_path):
    json_path = tmp_path / "out.json"
    with _patched_validators(cmdi_result=([], [], [_capability()])):
        result = runner.invoke(
            app, ["scan", str(case_dir), "--plain", "--classes", "command_injection", "--json", str(json_path)],
        )
    assert result.exit_code == 0
    payload = json.loads(json_path.read_text())

    cap = payload["capabilities"]["command_injection"][0]
    assert cap["bypassable_filter"] is False
    assert cap["blocked_techniques"] == []


def test_scan_plain_shows_bypassable_filter_note(case_dir):
    capability = _capability()
    capability["bypassable_filter"] = True
    capability["blocked_techniques"] = ["shell_pipe_bare"]
    with _patched_validators(cmdi_result=([], [], [capability])):
        result = runner.invoke(app, ["scan", str(case_dir), "--plain", "--classes", "command_injection"])

    assert result.exit_code == 0
    assert "filtro_eludible" in result.stdout
    assert "shell_semicolon_bare" in result.stdout
    assert "shell_pipe_bare" in result.stdout


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


# -- build --------------------------------------------------------------------

@pytest.fixture
def build_target(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "requirements.txt").write_text("mcp\n")
    return target


def _build_result(target):
    return build_mod.BuildResult(
        tag="lynceus-target:abc123def456",
        resolved_path=target.parent / "cache" / "requirements.resolved.txt",
        cache_dir=target.parent / "cache",
        versions=[("mcp", "1.30.0"), ("requests", "2.33.0")],
        skipped_image_build=False,
    )


def test_build_exit_code_2_when_target_is_not_a_directory(tmp_path):
    missing = tmp_path / "does-not-exist"
    result = runner.invoke(app, ["build", str(missing), "--requirements", "requirements.txt", "--plain"])
    assert result.exit_code == 2
    assert "no es una carpeta" in result.stdout


def test_build_requirements_rejects_path_outside_target(build_target):
    result = runner.invoke(app, ["build", str(build_target), "--requirements", "../requirements.txt", "--plain"])
    assert result.exit_code == 2
    assert "--requirements" in result.stdout


def test_build_requirements_rejects_absolute_path(build_target):
    result = runner.invoke(app, ["build", str(build_target), "--requirements", "/etc/passwd", "--plain"])
    assert result.exit_code == 2
    assert "--requirements" in result.stdout


def test_build_requirements_rejects_missing_file(build_target):
    result = runner.invoke(app, ["build", str(build_target), "--requirements", "missing.txt", "--plain"])
    assert result.exit_code == 2
    assert "no contiene el fichero de requisitos" in result.stdout


def test_build_resolve_date_rejects_bad_format(build_target):
    result = runner.invoke(
        app,
        ["build", str(build_target), "--requirements", "requirements.txt", "--resolve-date", "22-03-2025", "--plain"],
    )
    assert result.exit_code == 2
    assert "--resolve-date" in result.stdout


def test_build_exit_code_2_on_build_error(build_target):
    with patch("lynceus_sec.cli.build_mod.run_build", side_effect=build_mod.BuildError("sin binario: foopkg")):
        result = runner.invoke(app, ["build", str(build_target), "--requirements", "requirements.txt", "--plain"])
    assert result.exit_code == 2
    assert "foopkg" in result.stdout
    assert "Traceback" not in result.stdout


def test_build_exit_code_2_with_distinct_message_when_docker_is_not_responding(build_target):
    with patch(
        "lynceus_sec.cli.build_mod.run_build",
        side_effect=build_mod.BuildError("Docker no responde: ¿está en marcha?"),
    ):
        result = runner.invoke(app, ["build", str(build_target), "--requirements", "requirements.txt", "--plain"])
    assert result.exit_code == 2
    assert "Docker no responde" in result.stdout


def test_build_plain_shows_version_fallback_warning(build_target):
    result_with_warning = build_mod.BuildResult(
        tag="lynceus-target:abc123def456",
        resolved_path=build_target.parent / "cache" / "requirements.resolved.txt",
        cache_dir=build_target.parent / "cache",
        versions=[("mcp", "1.30.0")],
        skipped_image_build=False,
        warnings=["pyproject.toml no fija una versión estática de 'mcp-server-fetch'"],
    )
    with patch("lynceus_sec.cli.build_mod.run_build", return_value=result_with_warning):
        result = runner.invoke(app, ["build", str(build_target), "--requirements", "requirements.txt", "--plain"])
    assert result.exit_code == 0
    assert "mcp-server-fetch" in result.stdout


def test_build_exit_code_0_and_renders_tag_and_versions(build_target):
    with patch("lynceus_sec.cli.build_mod.run_build", return_value=_build_result(build_target)) as run_mock:
        result = runner.invoke(app, ["build", str(build_target), "--requirements", "requirements.txt", "--plain"])
    assert result.exit_code == 0
    assert "lynceus-target:abc123def456" in result.stdout
    assert "mcp" in result.stdout and "1.30.0" in result.stdout
    run_mock.assert_called_once_with(build_target, "requirements.txt", resolve_date=None)


def test_build_forwards_resolve_date(build_target):
    with patch("lynceus_sec.cli.build_mod.run_build", return_value=_build_result(build_target)) as run_mock:
        result = runner.invoke(
            app,
            ["build", str(build_target), "--requirements", "requirements.txt", "--resolve-date", "2025-03-22", "--plain"],
        )
    assert result.exit_code == 0
    run_mock.assert_called_once_with(build_target, "requirements.txt", resolve_date="2025-03-22")


def test_build_plain_flag_has_no_ansi_or_emoji(build_target):
    with patch("lynceus_sec.cli.build_mod.run_build", return_value=_build_result(build_target)):
        result = runner.invoke(app, ["build", str(build_target), "--requirements", "requirements.txt", "--plain"])
    assert not _ANSI_RE.search(result.stdout)
    assert not any(ch in result.stdout for ch in _EMOJI_CHARS)


def test_build_help_lists_options():
    result = runner.invoke(app, ["build", "--help"])
    assert result.exit_code == 0
    output = _strip_ansi(result.stdout)
    for option in ("--requirements", "--resolve-date", "--plain"):
        assert option in output


# -- clean --------------------------------------------------------------------

def _raise(exc):
    def _inner(*args, **kwargs):
        raise exc
    return _inner


def _patched_clean(
    *,
    docker_responding_error=None,
    cache_safety_error=None,
    images=(),
    remove_images_result=([], []),
    cache_path=Path("/tmp/fake-cache/build"),
    removed_cache_path=Path("/tmp/fake-cache/build"),
):
    """Mockea las cuatro llamadas de `validator.clean` que usa el comando
    `clean`, con las dos validaciones (`ensure_docker_responding`,
    `ensure_cache_removal_is_safe`) separadas de las dos acciones
    (`list_target_images`, `remove_images`, `remove_cache_dir`), igual que
    en el propio comando."""
    stack = ExitStack()
    stack.enter_context(patch(
        "lynceus_sec.cli.clean_mod.ensure_docker_responding",
        side_effect=_raise(docker_responding_error) if docker_responding_error else lambda: None,
    ))
    stack.enter_context(patch(
        "lynceus_sec.cli.clean_mod.ensure_cache_removal_is_safe",
        side_effect=_raise(cache_safety_error) if cache_safety_error else lambda: cache_path,
    ))
    list_mock = stack.enter_context(
        patch("lynceus_sec.cli.clean_mod.list_target_images", return_value=list(images))
    )
    remove_images_mock = stack.enter_context(
        patch("lynceus_sec.cli.clean_mod.remove_images", return_value=remove_images_result)
    )
    remove_cache_mock = stack.enter_context(
        patch("lynceus_sec.cli.clean_mod.remove_cache_dir", return_value=removed_cache_path)
    )
    return stack, list_mock, remove_images_mock, remove_cache_mock


def test_clean_without_yes_only_lists_and_removes_nothing():
    images = [clean_mod.TargetImage(tag="lynceus-target:abcdef123456", size="10MB")]
    stack, _, remove_images_mock, remove_cache_mock = _patched_clean(images=images)
    with stack:
        result = runner.invoke(app, ["clean", "--plain"])

    assert result.exit_code == 0
    assert "lynceus-target:abcdef123456" in result.stdout
    assert "10MB" in result.stdout
    remove_images_mock.assert_not_called()
    remove_cache_mock.assert_not_called()


def test_clean_without_yes_never_validates_cache_safety():
    """Sin --yes no se borra nada, así que no hace falta validar la caché."""
    images = [clean_mod.TargetImage(tag="lynceus-target:abcdef123456", size="10MB")]
    stack = ExitStack()
    stack.enter_context(patch("lynceus_sec.cli.clean_mod.ensure_docker_responding", return_value=None))
    cache_safety_mock = stack.enter_context(
        patch("lynceus_sec.cli.clean_mod.ensure_cache_removal_is_safe", side_effect=AssertionError("no debería llamar"))
    )
    stack.enter_context(patch("lynceus_sec.cli.clean_mod.list_target_images", return_value=images))
    with stack:
        result = runner.invoke(app, ["clean", "--plain"])

    assert result.exit_code == 0
    cache_safety_mock.assert_not_called()


def test_clean_validates_before_listing_or_removing_anything():
    """Orden exigido: primero las dos validaciones, luego listar/filtrar
    --keep, y solo al final borrar."""
    call_order = []
    stack = ExitStack()
    stack.enter_context(patch(
        "lynceus_sec.cli.clean_mod.ensure_docker_responding",
        side_effect=lambda: call_order.append("ensure_docker_responding"),
    ))
    stack.enter_context(patch(
        "lynceus_sec.cli.clean_mod.ensure_cache_removal_is_safe",
        side_effect=lambda: call_order.append("ensure_cache_removal_is_safe") or Path("/tmp/fake-cache/build"),
    ))
    stack.enter_context(patch(
        "lynceus_sec.cli.clean_mod.list_target_images",
        side_effect=lambda: call_order.append("list_target_images") or [],
    ))
    stack.enter_context(patch(
        "lynceus_sec.cli.clean_mod.remove_images",
        side_effect=lambda tags: call_order.append("remove_images") or ([], []),
    ))
    stack.enter_context(patch(
        "lynceus_sec.cli.clean_mod.remove_cache_dir",
        side_effect=lambda: call_order.append("remove_cache_dir") or Path("/tmp/fake-cache/build"),
    ))
    with stack:
        result = runner.invoke(app, ["clean", "--yes", "--plain"])

    assert result.exit_code == 0
    assert call_order == [
        "ensure_docker_responding", "ensure_cache_removal_is_safe",
        "list_target_images", "remove_images", "remove_cache_dir",
    ]


def test_clean_with_yes_removes_images_and_cache():
    images = [
        clean_mod.TargetImage(tag="lynceus-target:aaaaaaaaaaaa", size="10MB"),
        clean_mod.TargetImage(tag="lynceus-target:bbbbbbbbbbbb", size="20MB"),
    ]
    stack, _, remove_images_mock, _ = _patched_clean(
        images=images,
        remove_images_result=(["lynceus-target:aaaaaaaaaaaa", "lynceus-target:bbbbbbbbbbbb"], []),
        removed_cache_path=Path("/tmp/fake-cache/build"),
    )
    with stack:
        result = runner.invoke(app, ["clean", "--yes", "--plain"])

    assert result.exit_code == 0
    remove_images_mock.assert_called_once_with(["lynceus-target:aaaaaaaaaaaa", "lynceus-target:bbbbbbbbbbbb"])
    assert "lynceus-target:aaaaaaaaaaaa" in result.stdout
    assert "/tmp/fake-cache/build" in result.stdout


def test_clean_shows_plan_before_removing():
    images = [clean_mod.TargetImage(tag="lynceus-target:aaaaaaaaaaaa", size="10MB")]
    stack, _, _, _ = _patched_clean(
        images=images, remove_images_result=(["lynceus-target:aaaaaaaaaaaa"], []),
    )
    with stack:
        result = runner.invoke(app, ["clean", "--yes", "--plain"])

    assert result.exit_code == 0
    assert "a-borrar" in result.stdout
    assert "lynceus-target:aaaaaaaaaaaa" in result.stdout


def test_clean_keeps_images_matching_keep_option_and_never_removes_them():
    images = [
        clean_mod.TargetImage(tag="lynceus-target:aaaaaaaaaaaa", size="10MB"),
        clean_mod.TargetImage(tag="lynceus-target:bbbbbbbbbbbb", size="20MB"),
    ]
    stack, _, remove_images_mock, _ = _patched_clean(
        images=images, remove_images_result=(["lynceus-target:bbbbbbbbbbbb"], []), removed_cache_path=None,
    )
    with stack:
        result = runner.invoke(
            app, ["clean", "--yes", "--keep", "lynceus-target:aaaaaaaaaaaa", "--plain"],
        )

    assert result.exit_code == 0
    remove_images_mock.assert_called_once_with(["lynceus-target:bbbbbbbbbbbb"])
    called_tags = remove_images_mock.call_args.args[0]
    assert "lynceus-target:aaaaaaaaaaaa" not in called_tags
    assert "lynceus-target:aaaaaaaaaaaa" in result.stdout  # conservada


def test_clean_exit_code_2_when_docker_not_responding_and_removes_nothing():
    stack, list_mock, remove_images_mock, remove_cache_mock = _patched_clean(
        docker_responding_error=clean_mod.CleanError("Docker no responde: ¿está en marcha?"),
    )
    with stack:
        result = runner.invoke(app, ["clean", "--yes", "--plain"])

    assert result.exit_code == 2
    assert "Docker no responde" in result.stdout
    list_mock.assert_not_called()
    remove_images_mock.assert_not_called()
    remove_cache_mock.assert_not_called()


def test_clean_exit_code_2_when_cache_is_unsafe_and_removes_no_image():
    """Regresión: antes, con una caché insegura, `clean --yes` borraba todas
    las imágenes y solo después fallaba al intentar borrar la caché. Ahora
    la validación de la caché va antes que cualquier `docker rmi`."""
    stack, list_mock, remove_images_mock, remove_cache_mock = _patched_clean(
        cache_safety_error=clean_mod.CleanError(
            "La base de la caché de Lynceus es el directorio personal; se niega a borrar nada por seguridad."
        ),
    )
    with stack:
        result = runner.invoke(app, ["clean", "--yes", "--plain"])

    assert result.exit_code == 2
    assert "directorio personal" in result.stdout
    list_mock.assert_not_called()
    remove_images_mock.assert_not_called()
    remove_cache_mock.assert_not_called()


def test_clean_end_to_end_with_lynceus_cache_dir_at_home_never_calls_docker_rmi(monkeypatch, tmp_path):
    """Regresión con el escenario real reportado (`LYNCEUS_CACHE_DIR=$HOME`,
    simulado con tmp_path): usa las funciones reales de `validator.clean`
    (solo se mockea `subprocess.run` y `Path.home`), y comprueba que ni
    `docker images` ni `docker rmi` llegan a ejecutarse."""
    monkeypatch.setenv("LYNCEUS_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    docker_calls = []

    def fake_run(cmd, **kwargs):
        docker_calls.append(cmd)
        if cmd[:2] == ["docker", "info"]:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = runner.invoke(app, ["clean", "--yes", "--plain"])

    assert result.exit_code == 2
    assert "directorio personal" in result.stdout
    assert not any(cmd[:2] == ["docker", "images"] for cmd in docker_calls)
    assert not any(cmd[:2] == ["docker", "rmi"] for cmd in docker_calls)


def test_clean_help_lists_options():
    result = runner.invoke(app, ["clean", "--help"])
    assert result.exit_code == 0
    output = _strip_ansi(result.stdout)
    for option in ("--yes", "--keep", "--plain"):
        assert option in output


# -- ayuda --------------------------------------------------------------------

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(text: str) -> str:
    """Quita los códigos ANSI que Typer emite en CI (p. ej. bajo GITHUB_ACTIONS)."""
    return _ANSI_RE.sub("", text)


def test_root_help_lists_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "build" in result.stdout
    assert "clean" in result.stdout
    assert "bench" in result.stdout


def test_scan_help_lists_options():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    output = _strip_ansi(result.stdout)
    for option in ("--classes", "--json", "--report", "--fs-root", "--entry", "--pythonpath", "--image", "--plain"):
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
