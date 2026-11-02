from lynceus_sec.core.model import Finding, ReproductionCall, VulnClass
from lynceus_sec.report import (
    CLASS_LABELS,
    SEVERITY_LABELS,
    SSRF_RECEIVER_NOTE,
    count_phrase,
    format_calls,
    format_reproduction,
    group_findings,
)


def _finding(**overrides) -> Finding:
    defaults = {
        "case": "case-1", "rule_id": "cmdi-shell_semicolon_bare", "vuln_class": VulnClass.COMMAND_INJECTION,
        "tool": "git_log", "severity": "critical", "message": "m", "evidence": "Canario creado en /tmp/x",
        "validated": True, "parameter": "ref", "technique": "shell_semicolon_bare", "payload": "; touch /tmp/x",
        "reproduction": [ReproductionCall(tool="git_log", arguments={"ref": "; touch /tmp/x"})],
    }
    defaults.update(overrides)
    return Finding(**defaults)


def test_group_findings_merges_same_case_tool_parameter_class():
    f1 = _finding(technique="shell_semicolon_bare")
    f2 = _finding(technique="shell_and_bare", rule_id="cmdi-shell_and_bare")

    groups = group_findings([f1, f2])

    assert len(groups) == 1
    assert groups[0].techniques == ["shell_semicolon_bare", "shell_and_bare"]
    assert len(groups[0].findings) == 2


def test_group_findings_separates_different_tools_or_parameters():
    f1 = _finding(tool="git_log")
    f2 = _finding(tool="git_diff")
    f3 = _finding(parameter="depth")

    groups = group_findings([f1, f2, f3])

    assert len(groups) == 3


def test_group_findings_separates_different_cases_and_classes():
    f1 = _finding(case="case-1")
    f2 = _finding(case="case-2")
    f3 = _finding(vuln_class=VulnClass.SSRF, rule_id="ssrf-host_url")

    groups = group_findings([f1, f2, f3])

    assert len(groups) == 3


def test_group_findings_preserves_first_seen_order():
    f_b = _finding(tool="b_tool")
    f_a = _finding(tool="a_tool")

    groups = group_findings([f_b, f_a])

    assert [g.tool for g in groups] == ["b_tool", "a_tool"]


def test_malicious_tool_name_does_not_merge_into_another_groups_attribution():
    """Un nombre de herramienta diseñado para parecerse al de otro grupo (o a
    texto de atribución) no debe fusionarse ni confundirse: la clave de
    agrupación usa `tool`/`parameter` tal cual, nunca interpretados."""
    legit = _finding(tool="read_file", parameter="path")
    spoofed = _finding(
        tool="read_file' de la tool 'other_tool",
        parameter="path",
    )

    groups = group_findings([legit, spoofed])

    assert len(groups) == 2
    tools = {g.tool for g in groups}
    assert "read_file" in tools
    assert "read_file' de la tool 'other_tool" in tools
    # Cada grupo conserva exactamente sus propios hallazgos, sin mezclar técnicas.
    by_tool = {g.tool: g for g in groups}
    assert by_tool["read_file"].findings == [legit]
    assert by_tool["read_file' de la tool 'other_tool"].findings == [spoofed]


def test_format_reproduction_joins_multiple_calls():
    calls = [
        ReproductionCall(tool="fetch", arguments={"url": "http://recv:8080/tok"}),
        ReproductionCall(tool="process", arguments={"url": "http://recv:8080/tok", "flag": False}),
    ]
    text = format_reproduction(calls)
    assert text == "fetch(url='http://recv:8080/tok'); process(url='http://recv:8080/tok', flag=False)"


def test_format_reproduction_handles_missing_calls():
    assert format_reproduction(None) == "(no disponible)"
    assert format_reproduction([]) == "(no disponible)"


def test_class_and_severity_labels_cover_every_known_identifier():
    assert CLASS_LABELS["command_injection"] == "Inyección de comandos"
    assert CLASS_LABELS["path_traversal"] == "Path traversal"
    assert CLASS_LABELS["ssrf"] == "SSRF"
    assert SEVERITY_LABELS["critical"] == "Crítica"
    assert SEVERITY_LABELS["high"] == "Alta"


def test_count_phrase_uses_singular_for_one():
    assert count_phrase(1, "vulnerabilidad confirmada", "vulnerabilidades confirmadas") == (
        "1 vulnerabilidad confirmada"
    )


def test_count_phrase_uses_plural_for_zero_and_many():
    assert count_phrase(0, "inconcluso", "inconclusos") == "0 inconclusos"
    assert count_phrase(2, "inconcluso", "inconclusos") == "2 inconclusos"


def test_format_calls_returns_one_string_per_call():
    calls = [
        ReproductionCall(tool="fetch", arguments={"url": "http://recv:8080/tok"}),
        ReproductionCall(tool="process", arguments={"url": "http://recv:8080/tok", "flag": False}),
    ]
    assert format_calls(calls) == [
        "fetch(url='http://recv:8080/tok')",
        "process(url='http://recv:8080/tok', flag=False)",
    ]


def test_format_calls_handles_missing_calls():
    assert format_calls(None) == ["(no disponible)"]
    assert format_calls([]) == ["(no disponible)"]


def test_ssrf_receiver_note_mentions_temporary_setup_and_reproduction():
    assert "temporal" in SSRF_RECEIVER_NOTE
    assert "receptor propio" in SSRF_RECEIVER_NOTE
