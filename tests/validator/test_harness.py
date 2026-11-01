from lynceus_sec.validator.harness import (
    _classify_attempt,
    _looks_like_environment_error,
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
