from types import SimpleNamespace

from rich.console import Console

from lynceus_sec.cli_render import (
    is_plain_mode,
    render_findings_table,
    sanitize_untrusted,
)
from lynceus_sec.core.model import Finding, ReproductionCall, VulnClass


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
    # Una sola fila de vulnerabilidad, no una por técnica.
    assert out.count("tool=git_log parametro=ref") == 1


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
