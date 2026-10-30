from lynceus_sec.validator.cmdi import attempts_to_findings, build_attempts
from lynceus_sec.validator.payloads import build_payloads

TOOL = {
    "name": "git_log",
    "input_schema": {
        "type": "object",
        "properties": {
            "ref": {"title": "ref", "type": "string"},
            "depth": {"title": "depth", "type": "integer"},
            "note": {"title": "note", "type": "string"},
        },
        "required": ["ref", "depth"],
    },
}


def test_build_attempts_covers_every_string_param_with_every_payload():
    attempts = build_attempts([TOOL])
    payload_count = len(build_payloads())

    # "ref" (obligatorio) y "note" (opcional) son los dos parámetros string
    assert len(attempts) == 2 * payload_count
    assert {a["parameter"] for a in attempts} == {"ref", "note"}


def test_required_non_string_params_get_neutral_values():
    attempts = build_attempts([TOOL])

    for attempt in attempts:
        assert attempt["arguments"]["depth"] == 0


def test_targeted_param_holds_the_payload_and_is_not_overwritten():
    attempts = build_attempts([TOOL])

    for attempt in attempts:
        assert attempt["arguments"][attempt["parameter"]] == attempt["payload"]


def test_optional_untargeted_string_param_is_not_included():
    attempts = build_attempts([TOOL])

    ref_attempts = [a for a in attempts if a["parameter"] == "ref"]
    for attempt in ref_attempts:
        assert "note" not in attempt["arguments"]


def test_attempt_ids_are_unique():
    attempts = build_attempts([TOOL])

    ids = [a["id"] for a in attempts]
    assert len(ids) == len(set(ids))


def _attempt(attempt_id="id-1", tool="git_log", parameter="ref", technique="shell_semicolon_bare"):
    return {
        "id": attempt_id,
        "tool": tool,
        "parameter": parameter,
        "technique": technique,
        "payload": "; touch /tmp/x",
        "canary_path": "/tmp/x",
        "arguments": {"ref": "; touch /tmp/x", "depth": 0},
    }


def test_only_confirmed_attempts_produce_findings():
    attempts = [_attempt("id-1"), _attempt("id-2"), _attempt("id-3")]
    results = [
        {"id": "id-1", "status": "confirmed", "detail": None},
        {"id": "id-2", "status": "not_confirmed", "detail": None},
        {"id": "id-3", "status": "inconclusive", "detail": "TimeoutError: ..."},
    ]

    findings, inconclusive = attempts_to_findings("cmdi-01-vulnerable", attempts, results)

    assert len(findings) == 1
    assert findings[0].validated is True
    assert findings[0].case == "cmdi-01-vulnerable"
    assert findings[0].tool == "git_log"
    assert findings[0].evidence is not None

    assert len(inconclusive) == 1
    assert inconclusive[0]["id"] == "id-3"


def test_not_confirmed_attempts_are_silently_dropped():
    attempts = [_attempt("id-1")]
    results = [{"id": "id-1", "status": "not_confirmed", "detail": None}]

    findings, inconclusive = attempts_to_findings("cmdi-01-vulnerable", attempts, results)

    assert findings == []
    assert inconclusive == []


def test_missing_result_is_treated_as_inconclusive():
    attempts = [_attempt("id-1")]

    findings, inconclusive = attempts_to_findings("cmdi-01-vulnerable", attempts, [])

    assert findings == []
    assert len(inconclusive) == 1
    assert inconclusive[0]["status"] == "inconclusive"
