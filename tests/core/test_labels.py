from pathlib import Path

import pytest

from lynceus_sec.core.labels import load_labels
from lynceus_sec.core.model import VulnClass

BENCHMARK_DIR = Path(__file__).resolve().parents[2] / "benchmark" / "cases"


def test_load_real_benchmark_cases():
    labels_by_case = load_labels(BENCHMARK_DIR)

    assert len(labels_by_case) == 24

    all_labels = [label for labels in labels_by_case.values() for label in labels]
    assert len(all_labels) == 12
    assert {label.vuln_class for label in all_labels} == {
        VulnClass.COMMAND_INJECTION,
        VulnClass.PATH_TRAVERSAL,
        VulnClass.SSRF,
    }


def test_fixed_case_has_empty_labels():
    labels_by_case = load_labels(BENCHMARK_DIR)
    assert labels_by_case["ptrav-01-fixed"] == []


def _write_case(tmp_path: Path, case_id: str, content: str) -> Path:
    case_dir = tmp_path / case_id
    case_dir.mkdir()
    (case_dir / "labels.yaml").write_text(content)
    return tmp_path


def test_invalid_vuln_class_raises_clear_error(tmp_path):
    benchmark_dir = _write_case(
        tmp_path,
        "bad-01",
        """
case: bad-01
vulnerabilities:
  - class: sql_injection
    tool: query
    file: server.py
    parameter: q
""",
    )

    with pytest.raises(ValueError, match="bad-01"):
        load_labels(benchmark_dir)


def test_duplicate_label_raises_clear_error(tmp_path):
    benchmark_dir = _write_case(
        tmp_path,
        "dup-01",
        """
case: dup-01
vulnerabilities:
  - class: ssrf
    tool: fetch
    file: server.py
    parameter: url
  - class: ssrf
    tool: fetch
    file: server.py
    parameter: url
""",
    )

    with pytest.raises(ValueError, match="uplicada"):
        load_labels(benchmark_dir)


def test_case_field_mismatch_raises_clear_error(tmp_path):
    benchmark_dir = _write_case(
        tmp_path,
        "mismatch-01",
        """
case: other-id
vulnerabilities: []
""",
    )

    with pytest.raises(ValueError, match="mismatch-01"):
        load_labels(benchmark_dir)
