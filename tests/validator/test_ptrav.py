from pathlib import Path

from lynceus_sec.core.model import ReproductionCall
from lynceus_sec.validator import ptrav
from lynceus_sec.validator.payloads import (
    build_path_traversal_payloads,
    build_path_traversal_write_payloads,
)
from lynceus_sec.validator.ptrav import (
    attempts_to_findings,
    build_attempts,
    build_write_attempts,
)

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


# --- build_write_attempts: oráculo de escritura, mismo patrón que build_attempts ---


def test_build_write_attempts_covers_every_string_param_with_every_payload_plus_one_control():
    attempts = build_write_attempts([TOOL])
    write_payload_count = len(build_path_traversal_write_payloads())

    assert len(attempts) == 2 * (write_payload_count + 1)
    assert {a["parameter"] for a in attempts} == {"name", "note"}


def test_build_write_attempts_tags_write_and_write_positive_control_kinds():
    attempts = build_write_attempts([TOOL])

    by_kind: dict[str, int] = {}
    for attempt in attempts:
        by_kind[attempt["kind"]] = by_kind.get(attempt["kind"], 0) + 1

    write_payload_count = len(build_path_traversal_write_payloads())
    assert by_kind == {"write": 2 * write_payload_count, "write_positive_control": 2}


def test_build_write_attempts_threads_a_custom_fs_root_into_target_paths():
    attempts = build_write_attempts([TOOL], fs_root="/tmp/otro-limite")

    controls = [a for a in attempts if a["kind"] == "write_positive_control"]
    assert controls
    for control in controls:
        assert control["write_target_path"].startswith("/tmp/otro-limite/")


def test_write_attempts_required_non_string_params_get_neutral_values():
    attempts = build_write_attempts([TOOL])

    for attempt in attempts:
        assert attempt["arguments"]["max_bytes"] == 0


def test_write_attempts_targeted_param_holds_the_target_path():
    attempts = build_write_attempts([TOOL])

    for attempt in attempts:
        assert attempt["arguments"][attempt["parameter"]] == attempt["payload"]


def test_write_attempts_other_string_params_hold_the_token():
    attempts = build_write_attempts([TOOL])

    for attempt in attempts:
        other_string_param = "note" if attempt["parameter"] == "name" else "name"
        assert attempt["arguments"][other_string_param] == attempt["write_token"]


def test_write_attempts_carry_target_path_and_token_under_tmp():
    attempts = build_write_attempts([TOOL])

    for attempt in attempts:
        assert attempt["write_token"]
        assert attempt["write_target_path"].startswith("/tmp/")
        assert attempt["environment_markers"] == ("modulenotfounderror",)


def test_write_attempt_ids_are_unique():
    attempts = build_write_attempts([TOOL])

    ids = [a["id"] for a in attempts]
    assert len(ids) == len(set(ids))


def test_only_the_symlink_write_technique_carries_symlink_fields():
    attempts = build_write_attempts([TOOL])

    for attempt in attempts:
        if attempt["technique"] == "symlink_write":
            assert attempt["symlink_path"] is not None
            assert attempt["symlink_target"] is not None
            # El enlace apunta directamente a la ruta objetivo (enlace
            # "colgante"), no a una carpeta como en lectura.
            assert attempt["symlink_target"] == attempt["write_target_path"]
        elif attempt["kind"] == "write":
            assert attempt["symlink_path"] is None
            assert attempt["symlink_target"] is None


# --- build_write_attempts con tres parámetros de texto: write_file_tool(path,
# content, encoding), el caso real de filesystem-mcp-server v1.0.0 donde
# "encoding" recibía el token por error y todas las técnicas salían
# not_confirmed. Ninguno de los tests de arriba (con TOOL, dos parámetros de
# texto) lo detecta: con solo un candidato a contenido posible, el diseño
# nuevo coincide exactamente con el anterior.

THREE_TEXT_PARAM_TOOL = {
    "name": "write_file_tool",
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "content": {"type": "string"},
            "encoding": {"type": "string"},
        },
        "required": ["path", "content", "encoding"],
    },
}


def test_build_write_attempts_generates_one_variant_per_other_text_param_as_content_candidate():
    attempts = build_write_attempts([THREE_TEXT_PARAM_TOOL])
    write_payload_count = len(build_path_traversal_write_payloads())

    # S=3 parámetros de texto: S*(S-1)=6 combinaciones (path_param,
    # content_param); con 6 técnicas cada una, 36 intentos "write" más 6
    # controles positivos.
    by_kind: dict[str, int] = {}
    for attempt in attempts:
        by_kind[attempt["kind"]] = by_kind.get(attempt["kind"], 0) + 1
    assert by_kind == {
        "write": 3 * 2 * write_payload_count,
        "write_positive_control": 3 * 2,
    }


def test_build_write_attempts_tries_each_other_text_param_as_content_in_turn():
    attempts = build_write_attempts([THREE_TEXT_PARAM_TOOL])

    for path_param in ("path", "content", "encoding"):
        content_candidates = {a["content_parameter"] for a in attempts if a["parameter"] == path_param}
        expected = {"path", "content", "encoding"} - {path_param}
        assert content_candidates == expected


def test_build_write_attempts_path_param_never_receives_the_token():
    attempts = build_write_attempts([THREE_TEXT_PARAM_TOOL])

    for attempt in attempts:
        assert attempt["arguments"][attempt["parameter"]] != attempt["write_token"]
        assert attempt["arguments"][attempt["parameter"]] == attempt["payload"]


def test_build_write_attempts_content_param_receives_the_token():
    attempts = build_write_attempts([THREE_TEXT_PARAM_TOOL])

    for attempt in attempts:
        assert attempt["arguments"][attempt["content_parameter"]] == attempt["write_token"]


def test_build_write_attempts_third_text_param_gets_the_neutral_default_not_the_token():
    """El bug real: con path_param="path" y content_param="content",
    "encoding" no debe recibir el token (que rompería la llamada), sino un
    valor neutro válido ("utf-8")."""
    attempts = build_write_attempts([THREE_TEXT_PARAM_TOOL])

    for attempt in attempts:
        other_params = {"path", "content", "encoding"} - {attempt["parameter"], attempt["content_parameter"]}
        for other in other_params:
            assert attempt["arguments"][other] == "utf-8"
            assert attempt["arguments"][other] != attempt["write_token"]


def test_build_write_attempts_skips_a_text_param_with_no_other_text_param_to_carry_the_token():
    """S=1: sin otro parámetro de texto no hay dónde poner el token, y sin
    token `_confirm_write` nunca podría confirmar nada; no tiene sentido
    generar la llamada."""
    tool = {
        "name": "touch_file_tool",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    }

    assert build_write_attempts([tool]) == []


def test_build_write_attempts_two_text_params_matches_the_design_before_this_change():
    """Con S=2 solo hay un candidato a contenido posible por path_param:
    el nuevo diseño coincide exactamente con el anterior (14 intentos para
    TOOL), sin ningún cambio de comportamiento en el caso común."""
    attempts = build_write_attempts([TOOL])
    write_payload_count = len(build_path_traversal_write_payloads())

    assert len(attempts) == 2 * (write_payload_count + 1)


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


def _write_attempt(attempt_id="id-1", tool="write_doc", parameter="path", technique="dotdot_outside_write"):
    return {
        "id": attempt_id,
        "kind": "write",
        "tool": tool,
        "parameter": parameter,
        "technique": technique,
        "payload": "../../../../../../../../tmp/lynceus-outside/x",
        "write_target_path": "/tmp/lynceus-outside/x",
        "write_token": "lynceus-write-abc",
        "environment_markers": ("modulenotfounderror",),
        "arguments": {"path": "../../../../../../../../tmp/lynceus-outside/x", "content": "lynceus-write-abc"},
    }


def test_confirmed_write_attempt_produces_a_finding_naming_the_write_direction():
    attempts = [_write_attempt("id-1")]
    results = [{"id": "id-1", "status": "confirmed", "detail": None}]

    findings, inconclusive, positive_controls = attempts_to_findings("ptrav-01-vulnerable", attempts, results)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.validated is True
    assert finding.tool == "write_doc"
    assert finding.vuln_class.value == "path_traversal"
    assert finding.parameter == "path"
    assert finding.technique == "dotdot_outside_write"
    assert "escritura" in finding.message
    assert "/tmp/lynceus-outside/x" in finding.evidence
    assert finding.reproduction == [
        ReproductionCall(
            tool="write_doc",
            arguments={"path": "../../../../../../../../tmp/lynceus-outside/x", "content": "lynceus-write-abc"},
        )
    ]
    assert inconclusive == []
    assert positive_controls == []


def test_confirmed_read_attempt_still_names_the_read_direction():
    attempts = [_attempt("id-1")]
    results = [{"id": "id-1", "status": "confirmed", "detail": None}]

    findings, _inconclusive, _positive_controls = attempts_to_findings("ptrav-01-vulnerable", attempts, results)

    assert "lectura" in findings[0].message


def test_not_confirmed_write_attempt_is_silently_dropped():
    attempts = [_write_attempt("id-1")]
    results = [{"id": "id-1", "status": "not_confirmed", "detail": None}]

    findings, inconclusive, positive_controls = attempts_to_findings("ptrav-01-vulnerable", attempts, results)

    assert findings == []
    assert inconclusive == []
    assert positive_controls == []


def test_inconclusive_write_attempt_is_reported_separately():
    attempts = [_write_attempt("id-1")]
    results = [{"id": "id-1", "status": "inconclusive", "detail": "la ruta objetivo ya existía"}]

    findings, inconclusive, positive_controls = attempts_to_findings("ptrav-01-vulnerable", attempts, results)

    assert findings == []
    assert len(inconclusive) == 1
    assert positive_controls == []


def test_write_positive_control_attempts_never_produce_findings_and_report_their_status():
    control_attempt = _write_attempt("id-1")
    control_attempt["kind"] = "write_positive_control"
    results = [{"id": "id-1", "status": "confirmed", "detail": None}]

    findings, inconclusive, positive_controls = attempts_to_findings(
        "ptrav-01-vulnerable", [control_attempt], results
    )

    assert findings == []
    assert inconclusive == []
    assert len(positive_controls) == 1
    assert positive_controls[0]["status"] == "confirmed"


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
    write_payload_count = len(build_path_traversal_write_payloads())
    # "name" y "note" (ver TOOL arriba), cada uno con sus cargas de lectura +
    # control positivo de lectura, más sus cargas de escritura + control
    # positivo de escritura: validate_case combina ambos (ver build_attempts
    # + build_write_attempts en ptrav.validate_case).
    total_attempts = 2 * (payload_count + 1 + write_payload_count + 1)
    assert len(container_names) == 3
    assert len(set(container_names)) == 3
    assert sum(attempt_counts) == total_attempts
    assert findings == []
