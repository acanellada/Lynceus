from pathlib import Path

import pytest

from lynceus_sec.validator import ssrf
from lynceus_sec.validator.runner import RunnerError
from lynceus_sec.validator.ssrf import (
    _secondary_arguments,
    attempts_to_findings,
    build_attempts,
)

TOOL_FETCH = {
    "name": "fetch",
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "timeout": {"type": "integer"},
        },
        "required": ["url", "timeout"],
    },
}

TOOL_PROCESS = {
    "name": "process",
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "timeout": {"type": "integer"},
            "flag": {"type": "boolean"},
        },
        "required": ["url", "timeout", "flag"],
    },
}


# --- build_attempts: cargas y estructura en dos pasos ---


def test_build_attempts_covers_every_string_param_with_three_techniques():
    attempts = build_attempts([TOOL_FETCH, TOOL_PROCESS], "recv-name", "10.0.0.5")

    fetch_url_attempts = [a for a in attempts if a["tool"] == "fetch" and a["parameter"] == "url"]
    assert {a["technique"] for a in fetch_url_attempts} == {"host_url", "ip_url", "file_canary"}


def test_url_techniques_carry_a_token_file_technique_carries_a_canary():
    attempts = build_attempts([TOOL_FETCH], "recv-name", "10.0.0.5")

    for attempt in attempts:
        if attempt["technique"] in ("host_url", "ip_url"):
            assert attempt["token"]
            assert attempt["canary_path"] is None
            assert attempt["canary_content"] is None
        else:
            assert attempt["technique"] == "file_canary"
            assert attempt["token"] is None
            assert attempt["canary_path"].startswith("/tmp/")
            assert attempt["canary_content"]


def test_host_and_ip_payloads_target_the_receiver():
    attempts = build_attempts([TOOL_FETCH], "recv-name", "10.0.0.5")

    host_attempt = next(a for a in attempts if a["technique"] == "host_url")
    ip_attempt = next(a for a in attempts if a["technique"] == "ip_url")
    assert host_attempt["payload"].startswith("http://recv-name:8080/")
    assert ip_attempt["payload"].startswith("http://10.0.0.5:8080/")
    assert host_attempt["token"] != ip_attempt["token"]


def test_first_call_targets_the_tool_under_test_with_the_payload():
    attempts = build_attempts([TOOL_FETCH, TOOL_PROCESS], "recv-name", "10.0.0.5")

    for attempt in attempts:
        primary_call = attempt["calls"][0]
        assert primary_call["tool"] == attempt["tool"]
        assert primary_call["arguments"][attempt["parameter"]] == attempt["payload"]


def test_second_step_calls_every_other_tool_and_reuses_the_payload_by_name():
    attempts = build_attempts([TOOL_FETCH, TOOL_PROCESS], "recv-name", "10.0.0.5")

    fetch_attempt = next(
        a for a in attempts if a["tool"] == "fetch" and a["parameter"] == "url" and a["technique"] == "host_url"
    )
    assert len(fetch_attempt["calls"]) == 2
    secondary_call = fetch_attempt["calls"][1]
    assert secondary_call["tool"] == "process"
    # "url" aparecía en la primera llamada (la carga): se reutiliza.
    assert secondary_call["arguments"]["url"] == fetch_attempt["payload"]
    # "flag" no aparecía en la primera llamada (fetch no la tiene): neutro.
    assert secondary_call["arguments"]["flag"] is False


def test_finding_is_always_attributed_to_the_tool_that_received_the_payload():
    attempts = build_attempts([TOOL_FETCH, TOOL_PROCESS], "recv-name", "10.0.0.5")

    process_attempt = next(
        a for a in attempts if a["tool"] == "process" and a["parameter"] == "url" and a["technique"] == "host_url"
    )
    tools_called = [call["tool"] for call in process_attempt["calls"]]
    assert tools_called == ["process", "fetch"]
    assert process_attempt["tool"] == "process"


def test_single_tool_server_has_no_secondary_calls():
    attempts = build_attempts([TOOL_FETCH], "recv-name", "10.0.0.5")

    for attempt in attempts:
        assert len(attempt["calls"]) == 1


# --- _secondary_arguments: reutilización completa por nombre, no solo la carga ---


def test_secondary_arguments_reuse_every_primary_value_by_name_not_only_the_payload():
    tool = {
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "label": {"type": "string"},
                "extra": {"type": "integer"},
            },
            "required": ["url", "label", "extra"],
        }
    }
    # "url" es la carga; "label" es un valor neutro de la primera llamada;
    # "extra" no apareció en absoluto en la primera llamada.
    primary_arguments = {"url": "http://payload/tok-1", "label": "lynceus"}

    result = _secondary_arguments(tool, primary_arguments)

    assert result["url"] == "http://payload/tok-1"
    assert result["label"] == "lynceus"
    assert result["extra"] == 0


def test_secondary_arguments_use_own_neutral_value_when_param_absent_from_primary():
    tool = {
        "input_schema": {
            "type": "object",
            "properties": {"note": {"type": "string"}},
            "required": ["note"],
        }
    }

    result = _secondary_arguments(tool, primary_arguments={"url": "http://payload/tok-1"})

    assert result == {"note": "lynceus"}


# --- attempts_to_findings: el token del receptor manda sobre el harness ---


def _url_attempt(attempt_id="a1", token="tok-1", technique="host_url"):
    return {
        "id": attempt_id,
        "tool": "fetch",
        "parameter": "url",
        "technique": technique,
        "payload": f"http://recv-name:8080/{token}",
        "token": token,
        "canary_path": None,
        "canary_content": None,
    }


def _file_attempt(attempt_id="a2"):
    return {
        "id": attempt_id,
        "tool": "fetch",
        "parameter": "url",
        "technique": "file_canary",
        "payload": "file:///tmp/lynceus-canary-x",
        "token": None,
        "canary_path": "/tmp/lynceus-canary-x",
        "canary_content": "lynceus-secret-x",
    }


def test_token_seen_in_receiver_log_confirms_even_if_the_harness_says_not_confirmed():
    attempt = _url_attempt()
    results = [{"id": "a1", "status": "not_confirmed", "detail": "ConnectionRefusedError: ..."}]
    log_entries = [{"method": "GET", "path": "/tok-1", "host": "recv-name:8080"}]

    findings, inconclusive = attempts_to_findings("ssrf-01-vulnerable", [attempt], results, log_entries)

    assert len(findings) == 1
    assert findings[0].validated is True
    assert findings[0].vuln_class.value == "ssrf"
    assert findings[0].tool == "fetch"
    assert inconclusive == []


def test_token_seen_in_receiver_log_confirms_even_without_a_harness_result():
    attempt = _url_attempt()
    log_entries = [{"method": "GET", "path": "/tok-1", "host": "recv-name:8080"}]

    findings, inconclusive = attempts_to_findings("ssrf-01-vulnerable", [attempt], [], log_entries)

    assert len(findings) == 1
    assert inconclusive == []


def test_token_not_seen_falls_back_to_harness_status():
    attempt = _url_attempt()
    results = [{"id": "a1", "status": "not_confirmed", "detail": None}]

    findings, inconclusive = attempts_to_findings("ssrf-01-vulnerable", [attempt], results, log_entries=[])

    assert findings == []
    assert inconclusive == []


def test_token_not_seen_but_harness_reports_inconclusive():
    attempt = _url_attempt()
    results = [{"id": "a1", "status": "inconclusive", "detail": "TimeoutError: ..."}]

    findings, inconclusive = attempts_to_findings("ssrf-01-vulnerable", [attempt], results, log_entries=[])

    assert findings == []
    assert len(inconclusive) == 1


def test_file_canary_confirmation_trusts_the_harness_directly():
    attempt = _file_attempt()
    results = [{"id": "a2", "status": "confirmed", "detail": "lynceus-secret-x"}]

    findings, _inconclusive = attempts_to_findings("ssrf-01-vulnerable", [attempt], results, log_entries=[])

    assert len(findings) == 1
    assert "lynceus-secret-x" in findings[0].evidence


# --- validate_case: limpieza garantizada (red, receptor, servidor) ---


def _patch_happy_path_up_to(monkeypatch, *, fail_at: str, exc: BaseException):
    """Deja pasar la orquestación hasta `fail_at` y la hace fallar ahí."""
    calls: dict[str, list] = {"killed": [], "stopped": [], "removed": []}

    monkeypatch.setattr(ssrf, "create_internal_network", lambda: "lynceus-net-x")
    monkeypatch.setattr(ssrf, "kill_container", lambda name: calls["killed"].append(name))
    monkeypatch.setattr(ssrf, "stop_receiver", lambda name: calls["stopped"].append(name))
    monkeypatch.setattr(ssrf, "remove_network", lambda name: calls["removed"].append(name))

    def make_step(name):
        def step(*args, **kwargs):
            if name == fail_at:
                raise exc
            if name == "check_network_isolation":
                return None
            if name == "start_receiver":
                return ("lynceus-receiver-x", "10.0.0.5")
            if name == "run_harness":
                return [TOOL_FETCH]
            if name == "run_validate":
                return []
        return step

    for step_name in ("check_network_isolation", "start_receiver", "run_harness", "run_validate"):
        monkeypatch.setattr(ssrf, step_name, make_step(step_name))

    monkeypatch.setattr(ssrf, "read_receiver_log", lambda name: [])
    return calls


@pytest.mark.parametrize("fail_at", ["check_network_isolation", "start_receiver", "run_harness", "run_validate"])
def test_network_is_always_removed_even_if_a_step_fails(monkeypatch, fail_at):
    calls = _patch_happy_path_up_to(monkeypatch, fail_at=fail_at, exc=RunnerError("boom"))

    with pytest.raises(RunnerError, match="boom"):
        ssrf.validate_case(Path("/some/case"))

    assert calls["removed"] == ["lynceus-net-x"]


def test_receiver_is_stopped_if_a_later_step_fails(monkeypatch):
    calls = _patch_happy_path_up_to(monkeypatch, fail_at="run_harness", exc=RunnerError("boom"))

    with pytest.raises(RunnerError):
        ssrf.validate_case(Path("/some/case"))

    assert calls["stopped"] == ["lynceus-receiver-x"]


def test_receiver_is_not_stopped_if_it_never_started(monkeypatch):
    calls = _patch_happy_path_up_to(monkeypatch, fail_at="check_network_isolation", exc=RunnerError("boom"))

    with pytest.raises(RunnerError):
        ssrf.validate_case(Path("/some/case"))

    assert calls["stopped"] == []


def test_server_container_is_killed_by_name_even_on_keyboard_interrupt(monkeypatch):
    calls = _patch_happy_path_up_to(monkeypatch, fail_at="run_validate", exc=KeyboardInterrupt())

    with pytest.raises(KeyboardInterrupt):
        ssrf.validate_case(Path("/some/case"))

    # Dos nombres de servidor (descubrimiento y validación) se matan por nombre.
    assert len(calls["killed"]) == 2
    assert calls["stopped"] == ["lynceus-receiver-x"]
    assert calls["removed"] == ["lynceus-net-x"]
