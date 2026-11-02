from lynceus_sec.core.model import ReproductionCall
from lynceus_sec.validator.payloads import build_path_traversal_payloads
from lynceus_sec.validator.ptrav import attempts_to_findings, build_attempts

TOOL = {
    "name": "read_doc",
    "input_schema": {
        "type": "object",
        "properties": {
            "name": {"title": "name", "type": "string"},
            "max_bytes": {"title": "max_bytes", "type": "integer"},
            "note": {"title": "note", "type": "string"},
        },
        "required": ["name", "max_bytes"],
    },
}


def test_build_attempts_covers_every_string_param_with_every_payload():
    attempts = build_attempts([TOOL])
    payload_count = len(build_path_traversal_payloads())

    # "name" (obligatorio) y "note" (opcional) son los dos parámetros string
    assert len(attempts) == 2 * payload_count
    assert {a["parameter"] for a in attempts} == {"name", "note"}


def test_required_non_string_params_get_neutral_values():
    attempts = build_attempts([TOOL])

    for attempt in attempts:
        assert attempt["arguments"]["max_bytes"] == 0


def test_targeted_param_holds_the_payload():
    attempts = build_attempts([TOOL])

    for attempt in attempts:
        assert attempt["arguments"][attempt["parameter"]] == attempt["payload"]


def test_attempts_carry_canary_content_and_environment_markers():
    attempts = build_attempts([TOOL])

    for attempt in attempts:
        assert attempt["canary_content"]
        assert attempt["canary_path"].startswith("/tmp/")
        assert attempt["environment_markers"] == ("modulenotfounderror",)


def test_attempt_ids_are_unique():
    attempts = build_attempts([TOOL])

    ids = [a["id"] for a in attempts]
    assert len(ids) == len(set(ids))


def _attempt(attempt_id="id-1", tool="read_doc", parameter="name", technique="dotdot_bare"):
    return {
        "id": attempt_id,
        "tool": tool,
        "parameter": parameter,
        "technique": technique,
        "payload": "../../../../../../../../tmp/x",
        "canary_path": "/tmp/x",
        "canary_content": "lynceus-secret-abc",
        "environment_markers": ("modulenotfounderror",),
        "arguments": {"name": "../../../../../../../../tmp/x", "max_bytes": 0},
    }


def test_only_confirmed_attempts_produce_findings():
    attempts = [_attempt("id-1"), _attempt("id-2"), _attempt("id-3")]
    results = [
        {"id": "id-1", "status": "confirmed", "detail": None},
        {"id": "id-2", "status": "not_confirmed", "detail": None},
        {"id": "id-3", "status": "inconclusive", "detail": "TimeoutError: ..."},
    ]

    findings, inconclusive = attempts_to_findings("ptrav-01-vulnerable", attempts, results)

    assert len(findings) == 1
    assert findings[0].validated is True
    assert findings[0].case == "ptrav-01-vulnerable"
    assert findings[0].tool == "read_doc"
    assert findings[0].vuln_class.value == "path_traversal"
    assert "lynceus-secret-abc" in findings[0].evidence

    # Gravedad por clase: path traversal es alta (no es una puntuación CVSS).
    assert findings[0].severity == "high"
    assert findings[0].parameter == "name"
    assert findings[0].technique == "dotdot_bare"
    assert findings[0].payload == "../../../../../../../../tmp/x"
    assert findings[0].evidence == "Contenido del canario leído en la respuesta: 'lynceus-secret-abc'"
    assert findings[0].reproduction == [
        ReproductionCall(
            tool="read_doc",
            arguments={"name": "../../../../../../../../tmp/x", "max_bytes": 0},
        )
    ]

    assert len(inconclusive) == 1
    assert inconclusive[0]["id"] == "id-3"


def test_not_confirmed_attempts_are_silently_dropped():
    attempts = [_attempt("id-1")]
    results = [{"id": "id-1", "status": "not_confirmed", "detail": None}]

    findings, inconclusive = attempts_to_findings("ptrav-01-vulnerable", attempts, results)

    assert findings == []
    assert inconclusive == []


def test_missing_result_is_treated_as_inconclusive():
    attempts = [_attempt("id-1")]

    findings, inconclusive = attempts_to_findings("ptrav-01-vulnerable", attempts, [])

    assert findings == []
    assert len(inconclusive) == 1
    assert inconclusive[0]["status"] == "inconclusive"
