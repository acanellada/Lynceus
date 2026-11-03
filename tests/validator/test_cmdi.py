from lynceus_sec.core.model import ReproductionCall
from lynceus_sec.validator.cmdi import attempts_to_findings, build_attempts
from lynceus_sec.validator.payloads import build_payloads, build_probe_payload

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


def test_build_attempts_covers_every_string_param_with_every_payload_plus_probe():
    attempts = build_attempts([TOOL])
    payload_count = len(build_payloads())

    # "ref" (obligatorio) y "note" (opcional) son los dos parámetros string;
    # por cada uno, todas las cargas de inyección más una sonda de capacidad.
    assert len(attempts) == 2 * (payload_count + 1)
    assert {a["parameter"] for a in attempts} == {"ref", "note"}


def test_build_attempts_includes_one_capability_probe_per_tool_and_param():
    attempts = build_attempts([TOOL])

    probes = [a for a in attempts if a["kind"] == "probe"]
    assert {p["parameter"] for p in probes} == {"ref", "note"}
    for probe in probes:
        assert probe["technique"] == "capability_probe"
        assert probe["payload"] == f"touch {probe['canary_path']}"
        assert probe["arguments"][probe["parameter"]] == probe["payload"]


def test_injection_attempts_are_tagged_with_injection_kind():
    attempts = build_attempts([TOOL])

    injections = [a for a in attempts if a["kind"] == "injection"]
    assert len(injections) == 2 * len(build_payloads())


def test_build_probe_payload_has_no_metacharacters_or_prefix():
    probe = build_probe_payload()

    assert probe.value == f"touch {probe.canary_path}"


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


def _attempt(
    attempt_id="id-1", tool="git_log", parameter="ref", technique="shell_semicolon_bare",
    kind="injection", canary_path="/tmp/x",
):
    return {
        "id": attempt_id,
        "kind": kind,
        "tool": tool,
        "parameter": parameter,
        "technique": technique,
        "payload": "; touch /tmp/x" if kind == "injection" else f"touch {canary_path}",
        "canary_path": canary_path,
        "arguments": {"ref": "; touch /tmp/x", "depth": 0},
    }


def test_only_confirmed_attempts_produce_findings():
    attempts = [_attempt("id-1"), _attempt("id-2"), _attempt("id-3")]
    results = [
        {"id": "id-1", "status": "confirmed", "detail": None},
        {"id": "id-2", "status": "not_confirmed", "detail": None},
        {"id": "id-3", "status": "inconclusive", "detail": "TimeoutError: ..."},
    ]

    findings, inconclusive, capabilities = attempts_to_findings("cmdi-01-vulnerable", attempts, results)

    assert len(findings) == 1
    assert findings[0].validated is True
    assert findings[0].case == "cmdi-01-vulnerable"
    assert findings[0].tool == "git_log"
    assert findings[0].evidence is not None

    # Gravedad por clase: inyección de comandos es crítica (no es una puntuación CVSS).
    assert findings[0].severity == "critical"
    # Campos estructurados, no interpretados de `message`/`evidence`.
    assert findings[0].parameter == "ref"
    assert findings[0].technique == "shell_semicolon_bare"
    assert findings[0].payload == "; touch /tmp/x"
    assert findings[0].evidence == "Canario creado en /tmp/x"
    assert findings[0].reproduction == [
        ReproductionCall(tool="git_log", arguments={"ref": "; touch /tmp/x", "depth": 0})
    ]

    assert len(inconclusive) == 1
    assert inconclusive[0]["id"] == "id-3"
    assert capabilities == []


def test_not_confirmed_attempts_are_silently_dropped():
    attempts = [_attempt("id-1")]
    results = [{"id": "id-1", "status": "not_confirmed", "detail": None}]

    findings, inconclusive, capabilities = attempts_to_findings("cmdi-01-vulnerable", attempts, results)

    assert findings == []
    assert inconclusive == []
    assert capabilities == []


def test_missing_result_is_treated_as_inconclusive():
    attempts = [_attempt("id-1")]

    findings, inconclusive, capabilities = attempts_to_findings("cmdi-01-vulnerable", attempts, [])

    assert findings == []
    assert len(inconclusive) == 1
    assert inconclusive[0]["status"] == "inconclusive"
    assert capabilities == []


# --- Sonda de capacidad: clasificación como capacidad vs. vulnerabilidad ---


def test_confirmed_probe_groups_confirmed_injection_as_capability_not_finding():
    probe = _attempt("probe-1", kind="probe", technique="capability_probe", canary_path="/tmp/probe")
    injection = _attempt("inj-1", kind="injection")
    attempts = [probe, injection]
    results = [
        {"id": "probe-1", "status": "confirmed", "detail": None},
        {"id": "inj-1", "status": "confirmed", "detail": None},
    ]

    findings, inconclusive, capabilities = attempts_to_findings("cmdi-01-vulnerable", attempts, results)

    assert findings == []
    assert inconclusive == []
    assert len(capabilities) == 1
    capability = capabilities[0]
    assert capability["tool"] == "git_log"
    assert capability["parameter"] == "ref"
    assert capability["probe"]["payload"] == "touch /tmp/probe"
    assert capability["probe"]["evidence"] == "Canario creado en /tmp/probe"
    assert len(capability["confirmations"]) == 1
    assert capability["confirmations"][0]["technique"] == "shell_semicolon_bare"


def test_injection_confirmed_on_another_tool_without_probe_is_still_reported_as_vulnerability():
    """Un mismo servidor puede tener una tool con capacidad de ejecución de
    comandos (sonda confirmada) y otra tool distinta, sin esa capacidad, con
    una inyección real: la segunda debe seguir generando Finding."""
    probe = _attempt("probe-1", tool="run_shell", parameter="command", kind="probe", canary_path="/tmp/probe")
    capable_injection = _attempt("inj-1", tool="run_shell", parameter="command", kind="injection")
    other_tool_injection = _attempt("inj-2", tool="git_log", parameter="ref", kind="injection")
    attempts = [probe, capable_injection, other_tool_injection]
    results = [
        {"id": "probe-1", "status": "confirmed", "detail": None},
        {"id": "inj-1", "status": "confirmed", "detail": None},
        {"id": "inj-2", "status": "confirmed", "detail": None},
    ]

    findings, inconclusive, capabilities = attempts_to_findings("cmdi-01-vulnerable", attempts, results)

    assert len(findings) == 1
    assert findings[0].tool == "git_log"
    assert findings[0].validated is True

    assert inconclusive == []
    assert len(capabilities) == 1
    assert capabilities[0]["tool"] == "run_shell"


def test_unconfirmed_probe_does_not_create_a_capability():
    probe = _attempt("probe-1", kind="probe", technique="capability_probe")
    injection = _attempt("inj-1", kind="injection")
    attempts = [probe, injection]
    results = [
        {"id": "probe-1", "status": "not_confirmed", "detail": None},
        {"id": "inj-1", "status": "confirmed", "detail": None},
    ]

    findings, inconclusive, capabilities = attempts_to_findings("cmdi-01-vulnerable", attempts, results)

    assert capabilities == []
    assert inconclusive == []
    assert len(findings) == 1
