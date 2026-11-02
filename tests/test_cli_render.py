from types import SimpleNamespace

from lynceus_sec.cli_render import (
    extract_parameter,
    extract_payload,
    extract_technique,
    is_plain_mode,
    sanitize_untrusted,
)
from lynceus_sec.core.model import Finding, VulnClass


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


def test_extract_parameter_from_message():
    message = "Inyección de comandos confirmada en el parámetro 'cmd' de la tool 'run' (shell)"
    assert extract_parameter(message) == "cmd"


def test_extract_parameter_missing_returns_placeholder():
    assert extract_parameter("mensaje sin parámetro") == "—"


def test_extract_technique_strips_known_prefix():
    finding = Finding(
        case="x", rule_id="cmdi-shell_semicolon", vuln_class=VulnClass.COMMAND_INJECTION,
        tool="run", severity="high", message="m", evidence=None, validated=True,
    )
    assert extract_technique(finding) == "shell_semicolon"


def test_extract_payload_for_command_injection_evidence():
    evidence = "payload='; touch /tmp/x' canary=/tmp/x"
    assert extract_payload(evidence) == "'; touch /tmp/x'"


def test_extract_payload_for_ssrf_evidence_with_detail():
    evidence = "payload='http://169.254.169.254/' detail=token visto en el registro del receptor"
    assert extract_payload(evidence) == "'http://169.254.169.254/'"


def test_extract_payload_missing_returns_none():
    assert extract_payload(None) is None
    assert extract_payload("sin formato reconocido") is None


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
