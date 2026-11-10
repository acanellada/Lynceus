from pathlib import Path

from lynceus_sec.core.model import ReproductionCall
from lynceus_sec.validator import ptrav
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


def test_build_attempts_covers_every_string_param_with_every_payload_plus_one_control():
    attempts = build_attempts([TOOL])
    payload_count = len(build_path_traversal_payloads())

    # "name" (obligatorio) y "note" (opcional) son los dos parámetros string;
    # por cada uno, todas las cargas de traversal más un control positivo.
    assert len(attempts) == 2 * (payload_count + 1)
    assert {a["parameter"] for a in attempts} == {"name", "note"}


def test_build_attempts_tags_traversal_and_positive_control_kinds():
    attempts = build_attempts([TOOL])

    by_kind: dict[str, int] = {}
    for attempt in attempts:
        by_kind[attempt["kind"]] = by_kind.get(attempt["kind"], 0) + 1

    payload_count = len(build_path_traversal_payloads())
    assert by_kind == {"traversal": 2 * payload_count, "positive_control": 2}


def test_build_attempts_threads_a_custom_fs_root_into_canary_paths():
    attempts = build_attempts([TOOL], fs_root="/tmp/otro-limite")

    controls = [a for a in attempts if a["kind"] == "positive_control"]
    assert controls
    for control in controls:
        assert control["canary_path"].startswith("/tmp/otro-limite/")


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


def _attempt(attempt_id="id-1", tool="read_doc", parameter="name", technique="dotdot_outside"):
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

    findings, inconclusive, positive_controls = attempts_to_findings("ptrav-01-vulnerable", attempts, results)

    assert len(findings) == 1
    assert findings[0].validated is True
    assert findings[0].case == "ptrav-01-vulnerable"
    assert findings[0].tool == "read_doc"
    assert findings[0].vuln_class.value == "path_traversal"
    assert "lynceus-secret-abc" in findings[0].evidence

    # Gravedad por clase: path traversal es alta (no es una puntuación CVSS).
    assert findings[0].severity == "high"
    assert findings[0].parameter == "name"
    assert findings[0].technique == "dotdot_outside"
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
    assert positive_controls == []


def test_not_confirmed_attempts_are_silently_dropped():
    attempts = [_attempt("id-1")]
    results = [{"id": "id-1", "status": "not_confirmed", "detail": None}]

    findings, inconclusive, positive_controls = attempts_to_findings("ptrav-01-vulnerable", attempts, results)

    assert findings == []
    assert inconclusive == []
    assert positive_controls == []


def test_missing_result_is_treated_as_inconclusive():
    attempts = [_attempt("id-1")]

    findings, inconclusive, positive_controls = attempts_to_findings("ptrav-01-vulnerable", attempts, [])

    assert findings == []
    assert len(inconclusive) == 1
    assert positive_controls == []


def test_positive_control_attempts_never_produce_findings_and_report_their_status():
    control_attempt = _attempt("id-1")
    control_attempt["kind"] = "positive_control"
    results = [{"id": "id-1", "status": "confirmed", "detail": None}]

    findings, inconclusive, positive_controls = attempts_to_findings(
        "ptrav-01-vulnerable", [control_attempt], results
    )

    assert findings == []
    assert inconclusive == []
    assert len(positive_controls) == 1
    assert positive_controls[0]["status"] == "confirmed"


def test_positive_control_with_missing_result_is_reported_separately_from_inconclusive():
    control_attempt = _attempt("id-1")
    control_attempt["kind"] = "positive_control"

    findings, inconclusive, positive_controls = attempts_to_findings(
        "ptrav-01-vulnerable", [control_attempt], []
    )

    assert findings == []
    assert inconclusive == []
    assert len(positive_controls) == 1
    assert positive_controls[0]["status"] == "inconclusive"


# --- validate_case: --image / --server-python se reenvían a run_harness ---


def test_validate_case_forwards_image_and_server_python_to_run_harness(monkeypatch):
    received = {}

    def fake_run_harness(case_dir, **kwargs):
        received.update(kwargs)
        return []  # sin tools: validate_case devuelve antes de llamar a run_validate

    monkeypatch.setattr(ptrav, "run_harness", fake_run_harness)

    ptrav.validate_case(
        Path("/some/case"), image="lynceus-target:abc123def456", server_python="/opt/target/bin/python",
    )

    assert received["image"] == "lynceus-target:abc123def456"
    assert received["server_python"] == "/opt/target/bin/python"


# --- validate_case: --jobs > 1 reparte los intentos entre varios contenedores ---


def test_validate_case_jobs_1_calls_run_harness_and_run_validate_directly_without_a_pool(monkeypatch):
    monkeypatch.setattr(ptrav, "run_harness", lambda case_dir, **kwargs: [TOOL])

    received = {}

    def fake_run_validate(case_dir, attempts, **kwargs):
        received["kwargs"] = kwargs
        return [{"id": a["id"], "status": "not_confirmed", "detail": None} for a in attempts]

    monkeypatch.setattr(ptrav, "run_validate", fake_run_validate)

    findings, _inconclusive, _positive_controls = ptrav.validate_case(Path("/some/case"), jobs=1, ctx=None)

    assert findings == []
    assert "container_name" not in received["kwargs"]


def test_validate_case_splits_attempts_across_multiple_containers_when_jobs_above_one(monkeypatch):
    from lynceus_sec.validator import runner
    from lynceus_sec.validator.parallel import ParallelContext

    monkeypatch.setattr(ptrav, "run_harness", lambda case_dir, **kwargs: [TOOL])
    monkeypatch.setattr(ptrav, "kill_container", lambda name: None)
    monkeypatch.setattr(runner, "kill_container", lambda name: None)

    container_names = []
    attempt_counts = []

    def fake_run_validate(case_dir, attempts, **kwargs):
        container_names.append(kwargs["container_name"])
        attempt_counts.append(len(attempts))
        return [{"id": a["id"], "status": "not_confirmed", "detail": None} for a in attempts]

    monkeypatch.setattr(runner, "run_validate", fake_run_validate)

    ctx = ParallelContext.create(3)
    try:
        findings, _inconclusive, _positive_controls = ptrav.validate_case(Path("/some/case"), jobs=3, ctx=ctx)
    finally:
        ctx.shutdown()

    payload_count = len(build_path_traversal_payloads())
    total_attempts = 2 * (payload_count + 1)  # "name" y "note", ver TOOL arriba
    assert len(container_names) == 3
    assert len(set(container_names)) == 3
    assert sum(attempt_counts) == total_attempts
    assert findings == []
