from lynceus_sec.cli_env import EnvironmentInfo
from lynceus_sec.cli_html import build_html_report
from lynceus_sec.core.model import Finding, ReproductionCall, VulnClass

ENV = EnvironmentInfo(
    lynceus_version="0.0.1",
    sandbox_image="lynceus-sandbox:0.1",
    sandbox_image_id="sha256:deadbeef",
    base_image_ref="python:3.12-slim@sha256:aa94",
    declared_python_version="3.12",
    declared_mcp_version="1.30.0",
)


def _finding(**overrides) -> Finding:
    defaults = {
        "case": "x", "rule_id": "cmdi-shell", "vuln_class": VulnClass.COMMAND_INJECTION,
        "tool": "git_log", "severity": "critical", "message": "m", "evidence": "Canario creado en /tmp/x",
        "validated": True, "parameter": "ref", "technique": "shell", "payload": "; id",
        "reproduction": [ReproductionCall(tool="git_log", arguments={"ref": "; id"})],
    }
    defaults.update(overrides)
    return Finding(**defaults)


def _malicious_finding() -> Finding:
    return _finding(
        tool="<script>alert(document.cookie)</script>",
        parameter="\"><img src=x onerror=alert(1)>",
        evidence="Canario creado en /tmp/x <script>evil()</script>",
        reproduction=[ReproductionCall(tool="<script>x</script>", arguments={"ref": "<svg onload=alert(1)>"})],
    )


def test_html_report_escapes_malicious_tool_and_evidence():
    html_out = build_html_report(
        target="/tmp/case", classes=["command_injection"], findings=[_malicious_finding()],
        inconclusive_by_class={}, elapsed_seconds=1.0, environment=ENV,
    )
    assert "<script>alert(document.cookie)</script>" not in html_out
    assert "<script>evil()</script>" not in html_out
    assert "&lt;script&gt;" in html_out


def test_html_report_escapes_malicious_parameter_and_reproduction_call():
    html_out = build_html_report(
        target="/tmp/case", classes=["command_injection"], findings=[_malicious_finding()],
        inconclusive_by_class={}, elapsed_seconds=1.0, environment=ENV,
    )
    assert '"><img src=x onerror=alert(1)>' not in html_out
    assert "<svg onload=alert(1)>" not in html_out
    assert "&lt;svg onload=alert(1)&gt;" in html_out


def test_html_report_escapes_malicious_inconclusive_detail():
    inconclusive = {"ssrf": [{"tool": "<b>x</b>", "parameter": "url", "technique": "t", "detail": "<svg onload=alert(1)>"}]}
    html_out = build_html_report(
        target="/tmp/case", classes=["ssrf"], findings=[], inconclusive_by_class=inconclusive,
        elapsed_seconds=1.0, environment=ENV,
    )
    assert "<svg onload=alert(1)>" not in html_out
    assert "<b>x</b>" not in html_out


def test_html_report_has_csp_meta_blocking_everything_but_inline_style():
    html_out = build_html_report(
        target="/tmp/case", classes=["ssrf"], findings=[], inconclusive_by_class={},
        elapsed_seconds=1.0, environment=ENV,
    )
    assert '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">' in html_out


def test_html_report_has_no_javascript():
    html_out = build_html_report(
        target="/tmp/case", classes=["ssrf"], findings=[_malicious_finding()], inconclusive_by_class={},
        elapsed_seconds=1.0, environment=ENV,
    )
    assert "<script" not in html_out.lower()
    assert "javascript:" not in html_out.lower()
    assert "<img" not in html_out.lower()
    assert "<svg" not in html_out.lower()
    assert "&lt;img" in html_out.lower()


def test_html_report_includes_environment_info_and_declared_markers():
    html_out = build_html_report(
        target="/tmp/case", classes=["ssrf"], findings=[], inconclusive_by_class={},
        elapsed_seconds=1.0, environment=ENV,
    )
    assert "sha256:deadbeef" in html_out
    assert "python:3.12-slim@sha256:aa94" in html_out
    assert "3.12 (declarada)" in html_out
    assert "1.30.0 (declarada)" in html_out


def test_html_report_shows_unknown_for_missing_image_id():
    env = EnvironmentInfo(
        lynceus_version="0.0.1", sandbox_image="lynceus-sandbox:0.1", sandbox_image_id=None,
        base_image_ref=None, declared_python_version=None, declared_mcp_version=None,
    )
    html_out = build_html_report(
        target="/tmp/case", classes=["ssrf"], findings=[], inconclusive_by_class={},
        elapsed_seconds=1.0, environment=env,
    )
    assert "desconocido" in html_out


def test_html_report_groups_findings_into_one_row_per_vulnerability():
    f1 = _finding(technique="shell_semicolon_bare")
    f2 = _finding(technique="shell_and_bare", rule_id="cmdi-shell_and_bare")

    html_out = build_html_report(
        target="/tmp/case", classes=["command_injection"], findings=[f1, f2],
        inconclusive_by_class={}, elapsed_seconds=1.0, environment=ENV,
    )
    assert html_out.count("<td class=\"mono\">git_log</td>") == 1
    assert "shell_semicolon_bare" in html_out
    assert "shell_and_bare" in html_out


def test_html_report_shows_readable_class_and_severity_names():
    html_out = build_html_report(
        target="/tmp/case", classes=["command_injection"], findings=[_finding()],
        inconclusive_by_class={}, elapsed_seconds=1.0, environment=ENV,
    )
    assert "Inyección de comandos" in html_out
    assert "Crítica" in html_out
    assert "command_injection" not in html_out.split("<title>")[1]  # fuera de datos técnicos


def test_html_report_shows_severity_disclaimer():
    html_out = build_html_report(
        target="/tmp/case", classes=["command_injection"], findings=[_finding()],
        inconclusive_by_class={}, elapsed_seconds=1.0, environment=ENV,
    )
    assert "no es una puntuación CVSS" in html_out


def test_html_report_reproduction_call_comes_from_reproduction_field():
    html_out = build_html_report(
        target="/tmp/case", classes=["command_injection"], findings=[_finding()],
        inconclusive_by_class={}, elapsed_seconds=1.0, environment=ENV,
    )
    assert "git_log(ref=&#x27;; id&#x27;)" in html_out
