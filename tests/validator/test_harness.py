import argparse
import asyncio
import io
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest
from mcp.client.stdio import get_default_environment

from lynceus_sec.validator import harness
from lynceus_sec.validator.harness import (
    _classify_attempt,
    _confirm_write,
    _ensure_under_tmp,
    _load_attempts,
    _looks_like_environment_error,
    _prepare_home,
    _prepare_symlink,
    _resolve_interpreter,
    _run_one_write_attempt,
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


# --- Oráculo de escritura: enlace "colgante" (_prepare_symlink) y
# confirmación por subcadena (_confirm_write). `_ensure_under_tmp` exige que
# toda ruta caiga bajo /tmp, así que estas pruebas usan una carpeta propia
# real bajo /tmp (nunca fuera del repo: es la misma frontera que ya usa el
# resto del harness), borrada al terminar cada prueba.


@pytest.fixture
def tmp_under_tmp():
    base = Path(tempfile.mkdtemp(prefix="lynceus-harness-test-", dir="/tmp"))
    try:
        yield base
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_prepare_symlink_does_nothing_without_symlink_keys():
    _prepare_symlink({})  # no debe lanzar ni tocar el disco


def test_prepare_symlink_creates_a_dangling_link_when_target_does_not_exist(tmp_under_tmp):
    link_path = tmp_under_tmp / "link"
    target_path = tmp_under_tmp / "target"
    attempt = {"symlink_path": str(link_path), "symlink_target": str(target_path)}

    _prepare_symlink(attempt)

    assert link_path.is_symlink()
    assert os.readlink(link_path) == str(target_path)
    # El destino todavía no existe: enlace "colgante", condición del ajuste
    # pedido por el usuario para la técnica symlink_write.
    assert not link_path.exists()
    assert not target_path.exists()


def test_prepare_symlink_is_idempotent(tmp_under_tmp):
    link_path = tmp_under_tmp / "link"
    target_path = tmp_under_tmp / "target"
    attempt = {"symlink_path": str(link_path), "symlink_target": str(target_path)}

    _prepare_symlink(attempt)
    _prepare_symlink(attempt)  # no debe fallar ni recrear el enlace

    assert link_path.is_symlink()


def test_writing_through_the_dangling_symlink_is_visible_at_the_target_path(tmp_under_tmp):
    """Confirma el oráculo de escritura vía enlace: si algo escribe
    siguiendo el enlace (abriendo `link_path`), el contenido aparece en
    `target_path`, la ruta real que el harness comprueba tras la llamada."""
    link_path = tmp_under_tmp / "link"
    target_path = tmp_under_tmp / "target"
    attempt = {"symlink_path": str(link_path), "symlink_target": str(target_path)}

    _prepare_symlink(attempt)
    assert not target_path.exists()

    link_path.write_text("lynceus-write-xyz")  # simula al servidor escribiendo a través del enlace

    assert target_path.exists()
    assert target_path.read_text() == "lynceus-write-xyz"


def test_symlink_write_payload_is_compatible_with_prepare_symlink():
    """El enlace de la carga de producción (`build_path_traversal_write_payloads`)
    apunta directamente a la ruta objetivo, no a una carpeta: confirma que
    `_prepare_symlink` lo deja colgante, igual que en la prueba de arriba."""
    from lynceus_sec.validator.payloads import build_path_traversal_write_payloads

    payload = next(p for p in build_path_traversal_write_payloads() if p.technique == "symlink_write")
    attempt = {"symlink_path": payload.symlink_path, "symlink_target": payload.symlink_target}

    try:
        _prepare_symlink(attempt)
        link_path = Path(payload.symlink_path)
        assert link_path.is_symlink()
        assert not link_path.exists()
    finally:
        Path(payload.symlink_path).unlink(missing_ok=True)


def test_confirm_write_detects_token_as_substring(tmp_under_tmp):
    """Ajuste del usuario: subcadena, no igualdad exacta, para no perder una
    escritura real que el servidor envuelva o transforme."""
    target = tmp_under_tmp / "target"
    target.write_text("prefix-lynceus-write-abc-suffix")

    assert _confirm_write(target, "lynceus-write-abc") is True


def test_confirm_write_false_when_token_absent(tmp_under_tmp):
    target = tmp_under_tmp / "target"
    target.write_text("contenido sin relación")

    assert _confirm_write(target, "lynceus-write-abc") is False


def test_confirm_write_false_when_file_missing(tmp_under_tmp):
    target = tmp_under_tmp / "missing"

    assert _confirm_write(target, "lynceus-write-abc") is False


# --- _run_one_write_attempt: comprobación de preexistencia antes de llamar,
# y clasificación de los cuatro resultados (confirmed/not_confirmed/
# inconclusive por error de entorno/inconclusive por fallo de protocolo).
# `_call_once` se sustituye por un doble: arrancar un servidor real es
# responsabilidad de las pruebas de integración con Docker, no de estas.


def test_write_attempt_is_inconclusive_without_calling_when_target_already_exists(tmp_under_tmp, monkeypatch):
    target = tmp_under_tmp / "target"
    target.write_text("ya estaba aquí")

    called = False

    async def fake_call_once(server_path, attempt, interpreter):
        nonlocal called
        called = True
        return False, "no debería llegar a llamarse"

    monkeypatch.setattr(harness, "_call_once", fake_call_once)

    attempt = {
        "id": "w1", "write_target_path": str(target), "write_token": "lynceus-write-abc",
        "environment_markers": ("modulenotfounderror",),
    }

    result = asyncio.run(_run_one_write_attempt("/case/server.py", attempt, 5.0, "python"))

    assert result == {
        "id": "w1", "status": "inconclusive", "detail": "la ruta objetivo ya existía antes de la llamada",
    }
    assert called is False


def test_write_attempt_confirms_when_target_appears_with_token_substring(tmp_under_tmp, monkeypatch):
    target = tmp_under_tmp / "target"

    async def fake_call_once(server_path, attempt, interpreter):
        target.write_text("wrapped-lynceus-write-abc-wrapped")
        return False, "ok"

    monkeypatch.setattr(harness, "_call_once", fake_call_once)

    attempt = {
        "id": "w2", "write_target_path": str(target), "write_token": "lynceus-write-abc",
        "environment_markers": ("modulenotfounderror",),
    }

    result = asyncio.run(_run_one_write_attempt("/case/server.py", attempt, 5.0, "python"))

    assert result["status"] == "confirmed"


def test_write_attempt_not_confirmed_on_file_not_found_tool_error(tmp_under_tmp, monkeypatch):
    target = tmp_under_tmp / "target"

    async def fake_call_once(server_path, attempt, interpreter):
        return True, "FileNotFoundError: [Errno 2] No such file or directory"

    monkeypatch.setattr(harness, "_call_once", fake_call_once)

    attempt = {
        "id": "w3", "write_target_path": str(target), "write_token": "lynceus-write-abc",
        "environment_markers": ("modulenotfounderror",),
    }

    result = asyncio.run(_run_one_write_attempt("/case/server.py", attempt, 5.0, "python"))

    assert result["status"] == "not_confirmed"


def test_write_attempt_inconclusive_on_module_not_found_error(tmp_under_tmp, monkeypatch):
    target = tmp_under_tmp / "target"

    async def fake_call_once(server_path, attempt, interpreter):
        return True, "ModuleNotFoundError: No module named 'foo'"

    monkeypatch.setattr(harness, "_call_once", fake_call_once)

    attempt = {
        "id": "w4", "write_target_path": str(target), "write_token": "lynceus-write-abc",
        "environment_markers": ("modulenotfounderror",),
    }

    result = asyncio.run(_run_one_write_attempt("/case/server.py", attempt, 5.0, "python"))

    assert result["status"] == "inconclusive"


def test_write_attempt_inconclusive_on_protocol_timeout(tmp_under_tmp, monkeypatch):
    target = tmp_under_tmp / "target"

    async def fake_call_once(server_path, attempt, interpreter):
        await asyncio.sleep(10)
        return False, "nunca debería llegar aquí"

    monkeypatch.setattr(harness, "_call_once", fake_call_once)

    attempt = {
        "id": "w5", "write_target_path": str(target), "write_token": "lynceus-write-abc",
        "environment_markers": ("modulenotfounderror",),
    }

    result = asyncio.run(_run_one_write_attempt("/case/server.py", attempt, 0.05, "python"))

    assert result["status"] == "inconclusive"


def test_write_attempt_is_not_inconclusive_when_a_previous_attempt_already_created_the_shared_parent_dir(
    tmp_under_tmp, monkeypatch,
):
    """Regresión: bug real visto en filesystem-mcp-server v1.0.0. Dos
    técnicas de escritura comparten el directorio padre (p.ej. la carpeta
    hermana /tmp/lynceus-root-x/), pero cada una lleva su propio fichero
    objetivo (nombre único). Crear ese directorio al validar el primer
    intento no debe hacer que el segundo salga `inconclusive`: la
    comprobación de "no debe existir todavía" mira el fichero objetivo
    exacto, no su directorio padre."""
    shared_parent = tmp_under_tmp / "lynceus-root-x"
    target_a = shared_parent / "lynceus-write-aaa"
    target_b = shared_parent / "lynceus-write-bbb"

    async def fake_call_once(server_path, attempt, interpreter):
        Path(attempt["write_target_path"]).write_text(attempt["write_token"])
        return False, "ok"

    monkeypatch.setattr(harness, "_call_once", fake_call_once)

    attempt_a = {
        "id": "shared-a", "write_target_path": str(target_a), "write_token": "lynceus-write-aaa-token",
        "environment_markers": ("modulenotfounderror",),
    }
    attempt_b = {
        "id": "shared-b", "write_target_path": str(target_b), "write_token": "lynceus-write-bbb-token",
        "environment_markers": ("modulenotfounderror",),
    }

    result_a = asyncio.run(_run_one_write_attempt("/case/server.py", attempt_a, 5.0, "python"))
    assert result_a["status"] == "confirmed"
    assert shared_parent.is_dir()  # el primer intento ya creó el directorio padre compartido

    result_b = asyncio.run(_run_one_write_attempt("/case/server.py", attempt_b, 5.0, "python"))

    assert result_b["status"] == "confirmed"
    assert result_b["detail"] != "la ruta objetivo ya existía antes de la llamada"


# --- _load_attempts: el JSON de intentos llega por stdin (--attempts-stdin,
# lo que usa siempre runner.py) o por --attempts en argv (solo para invocar
# el harness a mano); evita el "argument list too long" de docker run con
# muchos intentos.


def _args(*, attempts_stdin: bool, attempts: str | None) -> argparse.Namespace:
    return argparse.Namespace(attempts_stdin=attempts_stdin, attempts=attempts)


def test_load_attempts_reads_json_from_stdin_when_flagged(monkeypatch):
    attempts = [{"id": "a1"}, {"id": "a2"}]
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(attempts)))

    result = _load_attempts(_args(attempts_stdin=True, attempts=None))

    assert result == attempts


def test_load_attempts_reads_json_from_attempts_arg_without_the_stdin_flag():
    attempts = [{"id": "a1"}, {"id": "a2"}]

    result = _load_attempts(_args(attempts_stdin=False, attempts=json.dumps(attempts)))

    assert result == attempts


def test_load_attempts_prefers_stdin_over_attempts_arg_when_both_are_given(monkeypatch):
    stdin_attempts = [{"id": "from-stdin"}]
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(stdin_attempts)))

    result = _load_attempts(_args(attempts_stdin=True, attempts=json.dumps([{"id": "from-argv"}])))

    assert result == stdin_attempts


def test_load_attempts_raises_without_either_source():
    with pytest.raises(ValueError, match="sin --attempts ni --attempts-stdin"):
        _load_attempts(_args(attempts_stdin=False, attempts=None))


def test_load_attempts_handles_many_attempts_from_stdin(monkeypatch):
    """Simula el caso real que dispara 'argument list too long': muchos
    intentos (500), leídos entero de stdin, nunca de argv."""
    attempts = [{"id": f"a{i}", "payload": "x" * 200} for i in range(500)]
    stdin_text = json.dumps(attempts)
    assert len(stdin_text) > 100_000  # el tamaño que antes iba en argv
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin_text))

    result = _load_attempts(_args(attempts_stdin=True, attempts=None))

    assert len(result) == 500
    assert result[0]["id"] == "a0"
    assert result[-1]["id"] == "a499"
