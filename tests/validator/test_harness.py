import os
import sys

import pytest
from mcp.client.stdio import get_default_environment

from lynceus_sec.validator.harness import (
    _classify_attempt,
    _ensure_under_tmp,
    _looks_like_environment_error,
    _prepare_home,
    _resolve_interpreter,
    _server_env,
)


def test_canary_present_with_protocol_error_is_confirmed():
    result = _classify_attempt("a1", canary_exists=True, error_kind="protocol", error_text="boom")

    assert result == {"id": "a1", "status": "confirmed", "detail": "boom"}


def test_canary_present_without_error_is_confirmed():
    result = _classify_attempt("a2", canary_exists=True, error_kind=None, error_text=None)

    assert result["status"] == "confirmed"


def test_infrastructure_failure_without_canary_is_inconclusive():
    result = _classify_attempt(
        "a3", canary_exists=False, error_kind="protocol", error_text="TimeoutError: deadline exceeded"
    )

    assert result == {"id": "a3", "status": "inconclusive", "detail": "TimeoutError: deadline exceeded"}


def test_environment_error_without_canary_is_inconclusive():
    detail = "FileNotFoundError: [Errno 2] No such file or directory: '/data/in.png'"
    result = _classify_attempt("a4", canary_exists=False, error_kind="tool", error_text=detail)

    assert result == {"id": "a4", "status": "inconclusive", "detail": detail}


def test_validation_error_without_canary_is_not_confirmed():
    detail = "ValueError: host inválido"
    result = _classify_attempt("a5", canary_exists=False, error_kind="tool", error_text=detail)

    assert result == {"id": "a5", "status": "not_confirmed", "detail": detail}


def test_success_without_canary_is_not_confirmed():
    result = _classify_attempt("a6", canary_exists=False, error_kind=None, error_text=None)

    assert result == {"id": "a6", "status": "not_confirmed", "detail": None}


def test_environment_error_detection_is_case_insensitive_substring():
    assert _looks_like_environment_error("ModuleNotFoundError: No module named 'requests'")
    assert _looks_like_environment_error("sh: 1: foo: not found")
    assert not _looks_like_environment_error("ValueError: referencia inválida")


# --- Tabla de clasificación con los marcadores de path_traversal: ---
# FileNotFoundError / "No such file or directory" ya no cuentan como error
# de entorno para esta clase (son una respuesta normal, no un fallo ajeno).

_PTRAV_MARKERS = ("modulenotfounderror",)


def test_ptrav_canary_leaked_with_tool_error_is_confirmed():
    result = _classify_attempt(
        "b1", canary_exists=True, error_kind="tool", error_text="boom",
        environment_markers=_PTRAV_MARKERS,
    )

    assert result == {"id": "b1", "status": "confirmed", "detail": "boom"}


def test_ptrav_infrastructure_failure_is_inconclusive():
    result = _classify_attempt(
        "b2", canary_exists=False, error_kind="protocol", error_text="TimeoutError: deadline exceeded",
        environment_markers=_PTRAV_MARKERS,
    )

    assert result == {"id": "b2", "status": "inconclusive", "detail": "TimeoutError: deadline exceeded"}


def test_ptrav_file_not_found_is_not_confirmed_not_inconclusive():
    detail = "FileNotFoundError: [Errno 2] No such file or directory: '/case/docs/x'"
    result = _classify_attempt(
        "b3", canary_exists=False, error_kind="tool", error_text=detail,
        environment_markers=_PTRAV_MARKERS,
    )

    assert result == {"id": "b3", "status": "not_confirmed", "detail": detail}


def test_ptrav_module_not_found_is_still_inconclusive():
    detail = "ModuleNotFoundError: No module named 'requests'"
    result = _classify_attempt(
        "b4", canary_exists=False, error_kind="tool", error_text=detail,
        environment_markers=_PTRAV_MARKERS,
    )

    assert result == {"id": "b4", "status": "inconclusive", "detail": detail}


def test_ptrav_other_tool_error_is_not_confirmed():
    detail = "ValueError: ruta fuera de docs"
    result = _classify_attempt(
        "b5", canary_exists=False, error_kind="tool", error_text=detail,
        environment_markers=_PTRAV_MARKERS,
    )

    assert result == {"id": "b5", "status": "not_confirmed", "detail": detail}


# --- --server-python: ruta fija de la imagen objetivo (ver TARGET_PYTHON) ---


def test_resolve_interpreter_defaults_to_sys_executable_when_none():
    assert _resolve_interpreter(None) == sys.executable


def test_resolve_interpreter_returns_the_path_when_it_exists(tmp_path):
    fake_python = tmp_path / "python"
    fake_python.write_text("")

    assert _resolve_interpreter(str(fake_python)) == str(fake_python)


def test_resolve_interpreter_raises_a_clear_error_when_missing():
    with pytest.raises(FileNotFoundError, match="Intérprete del servidor no encontrado"):
        _resolve_interpreter("/opt/target/bin/python")


# --- Defensa en profundidad: ninguna ruta fuera de /tmp, nunca se crea nada ---


def test_ensure_under_tmp_accepts_a_path_under_tmp():
    assert str(_ensure_under_tmp("/tmp/lynceus-root/escape", what="x")) == "/tmp/lynceus-root/escape"


def test_ensure_under_tmp_rejects_a_path_outside_tmp():
    with pytest.raises(ValueError, match="fuera de /tmp"):
        _ensure_under_tmp("/etc/passwd", what="canary_path")


def test_ensure_under_tmp_rejects_tmp_itself():
    with pytest.raises(ValueError, match="fuera de /tmp"):
        _ensure_under_tmp("/tmp", what="symlink_target")


def test_ensure_under_tmp_rejects_a_dotdot_escape_after_normalizing():
    with pytest.raises(ValueError, match="fuera de /tmp"):
        _ensure_under_tmp("/tmp/../etc/passwd", what="symlink_path")


def test_ensure_under_tmp_accepts_a_dotdot_that_stays_under_tmp_after_normalizing():
    result = _ensure_under_tmp("/tmp/a/../b", what="x")

    assert str(result) == "/tmp/b"


def test_prepare_home_rejects_a_home_outside_tmp_without_creating_it(monkeypatch):
    monkeypatch.setenv("HOME", "/etc/evil")

    with pytest.raises(ValueError, match="fuera de /tmp"):
        _prepare_home()

    assert not os.path.exists("/etc/evil")


# --- Reenvío de PYTHONPATH al subproceso del servidor analizado: ---
# `stdio_client` combina `env=` con `get_default_environment()` (ver
# mcp.client.stdio.stdio_client: `get_default_environment() | (server.env or
# {})`), nunca lo sustituye. `_server_env()` solo debe aportar PYTHONPATH.


def test_server_env_is_none_without_pythonpath(monkeypatch):
    monkeypatch.delenv("PYTHONPATH", raising=False)

    assert _server_env() is None


def test_server_env_carries_only_pythonpath(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/case/lib:/case/vendor")

    assert _server_env() == {"PYTHONPATH": "/case/lib:/case/vendor"}


def test_server_env_merged_with_sdk_defaults_keeps_home_and_adds_pythonpath(monkeypatch):
    """Reproduce exactamente la combinación que hace `stdio_client` del SDK
    instalado (`get_default_environment() | (server.env or {})`): comprueba
    que, con --pythonpath fijado, el servidor analizado sigue recibiendo
    HOME (y el resto de variables por defecto), no solo PYTHONPATH."""
    monkeypatch.setenv("HOME", "/tmp/lynceus-root")
    monkeypatch.setenv("PYTHONPATH", "/case/lib")

    merged = get_default_environment() | (_server_env() or {})

    assert merged["HOME"] == "/tmp/lynceus-root"
    assert merged["PYTHONPATH"] == "/case/lib"
