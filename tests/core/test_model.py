import pytest
from pydantic import ValidationError

from lynceus_sec.core.model import Finding, Label, ReproductionCall, VulnClass


def test_label_from_yaml_alias():
    label = Label(case="c1", **{"class": "path_traversal"}, tool="read_doc", file="server.py", parameter="name")
    assert label.vuln_class is VulnClass.PATH_TRAVERSAL


def test_label_from_field_name():
    label = Label(case="c1", vuln_class=VulnClass.SSRF, tool="fetch", file="server.py", parameter="url")
    assert label.vuln_class is VulnClass.SSRF


def test_label_rejects_invalid_class():
    with pytest.raises(ValidationError):
        Label(case="c1", **{"class": "sql_injection"}, tool="x", file="server.py", parameter="p")


def test_finding_defaults():
    finding = Finding(
        case="c1",
        rule_id="r1",
        vuln_class=VulnClass.COMMAND_INJECTION,
        tool="ping",
        severity="high",
        message="m",
    )
    assert finding.validated is False
    assert finding.evidence is None
    assert finding.parameter is None
    assert finding.technique is None
    assert finding.payload is None
    assert finding.reproduction is None


def test_finding_accepts_structured_fields():
    finding = Finding(
        case="c1",
        rule_id="r1",
        vuln_class=VulnClass.SSRF,
        tool="fetch",
        severity="high",
        message="m",
        parameter="url",
        technique="host_url",
        payload="http://recv:8080/tok-1",
        reproduction=[
            ReproductionCall(tool="fetch", arguments={"url": "http://recv:8080/tok-1"}),
            ReproductionCall(tool="process", arguments={"url": "http://recv:8080/tok-1", "flag": False}),
        ],
    )
    assert finding.parameter == "url"
    assert finding.technique == "host_url"
    assert finding.payload == "http://recv:8080/tok-1"
    assert len(finding.reproduction) == 2
    assert finding.reproduction[1].tool == "process"


def test_reproduction_call_rejects_extra_fields():
    with pytest.raises(ValidationError):
        ReproductionCall(tool="fetch", arguments={}, unexpected="nope")


def test_finding_rejects_extra_fields():
    with pytest.raises(ValidationError):
        Finding(
            case="c1",
            rule_id="r1",
            vuln_class=VulnClass.SSRF,
            tool="fetch",
            severity="high",
            message="m",
            unexpected="nope",
        )
