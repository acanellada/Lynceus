from types import SimpleNamespace

from rich.console import Console

from lynceus_sec.cli_render import (
    ScanSummary,
    is_plain_mode,
    render_findings_table,
    render_fs_root,
    render_inconclusive,
    render_positive_controls,
    render_summary,
    sanitize_untrusted,
)
from lynceus_sec.core.model import Finding, ReproductionCall, VulnClass
from lynceus_sec.report import SSRF_RECEIVER_NOTE


def test_sanitize_strips_ansi_escape_sequences():
    evil = "\x1b[31mrojo\x1b[0m normal"
    assert sanitize_untrusted(evil) == "rojo normal"


def test_sanitize_strips_osc_sequences():
    evil = "\x1b]0;título falso\x07resto"
    assert "\x1b" not in sanitize_untrusted(evil)
    assert "\x07" not in sanitize_untrusted(evil)


def test_sanitize_strips_control_characters_but_keeps_newline():
    evil = "linea1\x00\x01\x7f\nlinea2"
    result = sanitize_untrusted(evil)
    assert "\x00" not in result
    assert "\x7f" not in result
    assert "\n" in result


def test_sanitize_none_and_empty():
    assert sanitize_untrusted(None) == ""
    assert sanitize_untrusted("") == ""


def test_is_plain_mode_true_when_flag_set():
    stream = SimpleNamespace(isatty=lambda: True)
    assert is_plain_mode(plain_flag=True, stream=stream) is True


def test_is_plain_mode_true_for_no_color_env(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    stream = SimpleNamespace(isatty=lambda: True)
    assert is_plain_mode(plain_flag=False, stream=stream) is True


def test_is_plain_mode_true_for_non_interactive_stream(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    stream = SimpleNamespace(isatty=lambda: False)
    assert is_plain_mode(plain_flag=False, stream=stream) is True


def test_is_plain_mode_false_when_interactive_and_no_flag_or_env(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    stream = SimpleNamespace(isatty=lambda: True)
    assert is_plain_mode(plain_flag=False, stream=stream) is False


def _finding(**overrides) -> Finding:
    defaults = {
        "case": "case-1", "rule_id": "cmdi-shell_semicolon_bare", "vuln_class": VulnClass.COMMAND_INJECTION,
        "tool": "git_log", "severity": "critical", "message": "m", "evidence": "Canario creado en /tmp/x",
        "validated": True, "parameter": "ref", "technique": "shell_semicolon_bare", "payload": "; touch /tmp/x",
        "reproduction": [ReproductionCall(tool="git_log", arguments={"ref": "; touch /tmp/x"})],
    }
    defaults.update(overrides)
    return Finding(**defaults)


def test_render_findings_table_plain_groups_and_uses_readable_names(capsys):
    console = Console(no_color=True, force_terminal=False, soft_wrap=True)
    f1 = _finding(technique="shell_semicolon_bare")
    f2 = _finding(technique="shell_and_bare", rule_id="cmdi-shell_and_bare")

    render_findings_table(console, [f1, f2], plain=True)
    out = capsys.readouterr().out

    assert "Inyección de comandos" in out
    assert "Crítica" in out
    assert "tool=git_log" in out
    assert "shell_semicolon_bare" in out
    assert "shell_and_bare" in out
    assert "git_log(ref='; touch /tmp/x')" in out
    # Una sola vulnerabilidad, no una por técnica: aparece una vez en el
    # resumen enumerado y una vez en la cabecera de su bloque de detalle.
    assert out.count("tool=git_log parametro=ref") == 2
    assert "[2]" not in out


def test_render_findings_table_plain_shows_severity_note(capsys):
    console = Console(no_color=True, force_terminal=False, soft_wrap=True)
    render_findings_table(console, [_finding()], plain=True)
    out = capsys.readouterr().out
    assert "no es una puntuación CVSS" in out


def test_render_findings_table_builds_reproduction_from_field_not_message(capsys):
    """La reproducción viene de `Finding.reproduction`; un `message` sin
    ningún formato reconocible no debe impedir que se muestre la llamada."""
    console = Console(no_color=True, force_terminal=False, soft_wrap=True)
    finding = _finding(message="texto libre sin comillas ni formato especial")

    render_findings_table(console, [finding], plain=True)
    out = capsys.readouterr().out

    assert "git_log(ref='; touch /tmp/x')" in out


def test_render_findings_table_empty_prints_nothing(capsys):
    console = Console(no_color=True, force_terminal=False, soft_wrap=True)
    render_findings_table(console, [], plain=True)
    out = capsys.readouterr().out
    assert out == ""


def test_render_findings_table_plain_shows_ssrf_note_only_for_ssrf_group(capsys):
    console = Console(no_color=True, force_terminal=False, soft_wrap=True)
    cmdi_finding = _finding()
    ssrf_finding = _finding(
        vuln_class=VulnClass.SSRF, rule_id="ssrf-host_url", technique="host_url",
        tool="fetch", parameter="url",
        reproduction=[ReproductionCall(tool="fetch", arguments={"url": "http://recv:8080/tok"})],
    )

    render_findings_table(console, [cmdi_finding, ssrf_finding], plain=True)
    out = capsys.readouterr().out

    assert out.count(SSRF_RECEIVER_NOTE) == 1


def test_render_findings_table_rich_keeps_reproduction_url_on_one_line():
    """La reproducción de SSRF va en el bloque a todo el ancho, no en una
    columna estrecha: una URL de longitud normal no debe partirse."""
    console = Console(record=True, width=100)
    url = "http://lynceus-receiver-abc123def456:8080/9f86d081884c7d659a2f"
    finding = _finding(
        vuln_class=VulnClass.SSRF, rule_id="ssrf-host_url", tool="fetch", parameter="url", technique="host_url",
        reproduction=[ReproductionCall(tool="fetch", arguments={"url": url})],
    )

    render_findings_table(console, [finding], plain=False)
    out = console.export_text()

    assert url in out


def test_render_findings_table_rich_has_summary_table_and_detail_block():
    console = Console(record=True, width=100)
    finding = _finding()

    render_findings_table(console, [finding], plain=False)
    out = console.export_text()

    assert "Técnicas" in out  # columna de la tabla resumen
    assert "Vulnerabilidad 1" in out  # cabecera del bloque de detalle


def test_render_summary_plain_uses_singular_for_one_vulnerability_and_technique(capsys):
    console = Console(no_color=True, force_terminal=False, soft_wrap=True)
    summary = ScanSummary(vulnerabilities=1, techniques=1, inconclusive=0, elapsed_seconds=0.5)

    render_summary(console, summary, plain=True)
    out = capsys.readouterr().out

    assert "1 vulnerabilidad confirmada (1 técnica)" in out


def test_render_summary_plain_uses_plural_for_many(capsys):
    console = Console(no_color=True, force_terminal=False, soft_wrap=True)
    summary = ScanSummary(vulnerabilities=2, techniques=3, inconclusive=1, elapsed_seconds=0.5)

    render_summary(console, summary, plain=True)
    out = capsys.readouterr().out

    assert "2 vulnerabilidades confirmadas (3 técnicas)" in out
    assert "1 inconcluso" in out


def test_render_inconclusive_plain_uses_singular_for_one_item(capsys):
    console = Console(no_color=True, force_terminal=False, soft_wrap=True)
    inconclusive = {"ssrf": [{"tool": "x", "parameter": "y", "technique": "z", "detail": "d"}]}

    render_inconclusive(console, inconclusive, plain=True)
    out = capsys.readouterr().out

    assert "1 intento inconcluso:" in out


def test_render_inconclusive_rich_title_uses_plural_for_many():
    console = Console(record=True, width=100)
    inconclusive = {
        "ssrf": [
            {"tool": "x", "parameter": "y", "technique": "z", "detail": "d"},
            {"tool": "x2", "parameter": "y2", "technique": "z2", "detail": "d2"},
        ]
    }

    render_inconclusive(console, inconclusive, plain=False)
    out = console.export_text()

    assert "2 intentos inconclusos" in out


def test_render_fs_root_plain_shows_the_limit(capsys):
    console = Console(no_color=True, force_terminal=False, soft_wrap=True)

    render_fs_root(console, "/tmp/lynceus-root", plain=True)
    out = capsys.readouterr().out

    assert "/tmp/lynceus-root" in out


def test_render_positive_controls_is_silent_when_empty(capsys):
    console = Console(no_color=True, force_terminal=False, soft_wrap=True)

    render_positive_controls(console, {}, plain=True)
    out = capsys.readouterr().out

    assert out == ""


def test_render_positive_controls_plain_shows_status_per_item(capsys):
    console = Console(no_color=True, force_terminal=False, soft_wrap=True)
    positive_controls = {"path_traversal": [{"tool": "read_doc", "parameter": "name", "status": "confirmed"}]}

    render_positive_controls(console, positive_controls, plain=True)
    out = capsys.readouterr().out

    assert "1 control positivo" in out
    assert "read_doc" in out
    assert "confirmed" in out
