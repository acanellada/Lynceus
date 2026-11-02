from lynceus_sec.cli_env import EnvironmentInfo
from lynceus_sec.cli_html import build_html_report
from lynceus_sec.core.model import Finding, VulnClass

ENV = EnvironmentInfo(
    lynceus_version="0.0.1",
    sandbox_image="lynceus-sandbox:0.1",
    sandbox_image_id="sha256:deadbeef",
    base_image_ref="python:3.12-slim@sha256:aa94",
    declared_python_version="3.12",
    declared_mcp_version="1.30.0",
)


def _malicious_finding() -> Finding:
    return Finding(
        case="x", rule_id="cmdi-shell", vuln_class=VulnClass.COMMAND_INJECTION,
        tool="<script>alert(document.cookie)</script>",
        severity="high",
        message="Inyección de comandos confirmada en el parámetro "
                "'\"><img src=x onerror=alert(1)>' de la tool 'x' (shell)",
        evidence="payload='; id #' canary=/tmp/x <script>evil()</script>",
        validated=True,
    )


def test_html_report_escapes_malicious_tool_and_evidence():
    html_out = build_html_report(
        target="/tmp/case", classes=["command_injection"], findings=[_malicious_finding()],
        inconclusive_by_class={}, elapsed_seconds=1.0, environment=ENV,
    )
    assert "<script>alert(document.cookie)</script>" not in html_out
    assert "<script>evil()</script>" not in html_out
    assert "&lt;script&gt;" in html_out


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
    # El payload original llevaba <img ...onerror=...> y <svg ...onload=...>; deben
    # aparecer solo como texto inerte escapado, nunca como etiquetas reales.
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
