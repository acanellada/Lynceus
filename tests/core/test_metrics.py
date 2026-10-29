import pytest

from lynceus_sec.core.metrics import compute_metrics
from lynceus_sec.core.model import Finding, Label, VulnClass


def _finding(case, vuln_class, tool, rule_id="r") -> Finding:
    return Finding(
        case=case,
        rule_id=rule_id,
        vuln_class=vuln_class,
        tool=tool,
        severity="high",
        message="m",
    )


def _label(case, vuln_class, tool) -> Label:
    return Label(case=case, vuln_class=vuln_class, tool=tool, file="server.py", parameter="p")


def test_no_findings_no_labels_yields_none():
    metrics = compute_metrics([], {})

    assert metrics.tp == 0
    assert metrics.fp == 0
    assert metrics.fn == 0
    assert metrics.precision is None
    assert metrics.recall is None
    for class_metrics in metrics.by_class.values():
        assert class_metrics.precision is None
        assert class_metrics.recall is None

    assert set(metrics.by_class) == set(VulnClass)


def test_two_tp_one_fp_one_fn():
    labels = {
        "c1": [_label("c1", VulnClass.PATH_TRAVERSAL, "read_doc")],
        "c2": [_label("c2", VulnClass.SSRF, "fetch")],
        "c3": [_label("c3", VulnClass.COMMAND_INJECTION, "ping")],
        "c4": [],
    }
    findings = [
        _finding("c1", VulnClass.PATH_TRAVERSAL, "read_doc"),  # TP
        _finding("c2", VulnClass.SSRF, "fetch"),  # TP
        _finding("c4", VulnClass.COMMAND_INJECTION, "exec"),  # FP
    ]

    metrics = compute_metrics(findings, labels)

    assert metrics.tp == 2
    assert metrics.fp == 1
    assert metrics.fn == 1
    assert metrics.precision == pytest.approx(2 / 3)
    assert metrics.recall == pytest.approx(2 / 3)

    assert metrics.by_class[VulnClass.COMMAND_INJECTION].fp == 1
    assert metrics.by_class[VulnClass.COMMAND_INJECTION].fn == 1
    assert metrics.by_class[VulnClass.PATH_TRAVERSAL].tp == 1
    assert metrics.by_class[VulnClass.SSRF].tp == 1


def test_no_findings_with_labels_precision_none_recall_zero():
    labels = {"c1": [_label("c1", VulnClass.PATH_TRAVERSAL, "read_doc")]}

    metrics = compute_metrics([], labels)

    assert metrics.tp == 0
    assert metrics.fn == 1
    assert metrics.precision is None
    assert metrics.recall == pytest.approx(0.0)


def test_duplicate_findings_count_once():
    labels = {"c1": [_label("c1", VulnClass.SSRF, "fetch")]}
    findings = [
        _finding("c1", VulnClass.SSRF, "fetch", rule_id="rule-a"),
        _finding("c1", VulnClass.SSRF, "fetch", rule_id="rule-b"),
    ]

    metrics = compute_metrics(findings, labels)

    assert metrics.tp == 1
    assert metrics.fp == 0
    assert metrics.fn == 0


def test_finding_with_unknown_case_raises():
    findings = [_finding("unknown-case", VulnClass.SSRF, "fetch")]

    with pytest.raises(ValueError, match="unknown-case"):
        compute_metrics(findings, {})
