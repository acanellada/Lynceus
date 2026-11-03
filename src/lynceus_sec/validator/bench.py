"""Valida dinámicamente los casos de una clase de vulnerabilidad y calcula sus métricas.

Ejecuta cargas con canarios dentro del sandbox, confirma los hallazgos con el
oráculo de Lynceus (nunca con lo que reporte el servidor) e informa aparte de
los intentos inconclusos.

Lógica compartida entre `scripts/eval_dynamic.py` (una clase a la vez, por
compatibilidad) y `lynceus bench` (las tres clases, con tabla agregada). Sin
`print`: quien llama decide cómo mostrar el progreso, mediante los callbacks
`on_case_start`/`on_case_done`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from lynceus_sec.core.labels import load_labels
from lynceus_sec.core.metrics import Metrics, compute_metrics
from lynceus_sec.core.model import Finding, Label, VulnClass
from lynceus_sec.validator.runner import RunnerError

ROOT = Path(__file__).resolve().parents[3]
BENCH = ROOT / "benchmark" / "cases"

CLASS_CONFIG = {
    "command_injection": {"prefix": "cmdi-", "vuln_class": VulnClass.COMMAND_INJECTION},
    "path_traversal": {"prefix": "ptrav-", "vuln_class": VulnClass.PATH_TRAVERSAL},
    "ssrf": {"prefix": "ssrf-", "vuln_class": VulnClass.SSRF},
}


def validate_case_for(vuln_class: VulnClass):
    if vuln_class is VulnClass.COMMAND_INJECTION:
        from lynceus_sec.validator.cmdi import validate_case
    elif vuln_class is VulnClass.PATH_TRAVERSAL:
        from lynceus_sec.validator.ptrav import validate_case
    else:
        from lynceus_sec.validator.ssrf import validate_case
    return validate_case


@dataclass
class CaseResult:
    case_id: str
    findings: list[Finding] = field(default_factory=list)
    inconclusive: list[dict] = field(default_factory=list)
    error: str | None = None


@dataclass
class BenchResult:
    class_name: str
    vuln_class: VulnClass
    case_results: list[CaseResult]
    all_findings: list[Finding]
    labels: dict[str, list[Label]]
    inconclusive_by_case: dict[str, list[dict]]
    metrics: Metrics
    missed_due_to_inconclusive: int


OnCaseStart = Callable[[str], None]
OnCaseDone = Callable[[CaseResult], None]


def run_class_benchmark(
    class_name: str,
    *,
    bench_dir: Path | None = None,
    on_case_start: OnCaseStart | None = None,
    on_case_done: OnCaseDone | None = None,
) -> BenchResult:
    """Ejecuta la validación dinámica de `class_name` sobre `bench_dir` (por defecto `benchmark/cases`)."""
    bench_dir = bench_dir or BENCH
    config = CLASS_CONFIG[class_name]
    prefix = config["prefix"]
    vuln_class = config["vuln_class"]
    validate_case = validate_case_for(vuln_class)

    labels_by_case = load_labels(bench_dir)
    cases = sorted(p for p in bench_dir.iterdir() if p.is_dir() and p.name.startswith(prefix))
    class_labels = {case_id: labels for case_id, labels in labels_by_case.items() if case_id.startswith(prefix)}

    case_results: list[CaseResult] = []
    all_findings: list[Finding] = []
    inconclusive_by_case: dict[str, list[dict]] = {}

    for case_dir in cases:
        case_id = case_dir.name
        if on_case_start is not None:
            on_case_start(case_id)
        try:
            # path_traversal devuelve un tercer elemento (controles positivos,
            # informativos) que bench no usa para las métricas; se ignora.
            result = validate_case(case_dir)
            findings, inconclusive = result[0], result[1]
        except RunnerError as exc:
            result = CaseResult(case_id=case_id, error=str(exc))
            case_results.append(result)
            if on_case_done is not None:
                on_case_done(result)
            continue

        result = CaseResult(case_id=case_id, findings=findings, inconclusive=inconclusive)
        case_results.append(result)
        if inconclusive:
            inconclusive_by_case[case_id] = inconclusive
        all_findings.extend(findings)
        if on_case_done is not None:
            on_case_done(result)

    metrics = compute_metrics(all_findings, class_labels)

    labeled_tool_keys = {
        (case_id, label.tool)
        for case_id, labels in class_labels.items()
        for label in labels
    }
    found_tool_keys = {(finding.case, finding.tool) for finding in all_findings}
    inconclusive_tool_keys = {
        (case_id, item["tool"])
        for case_id, items in inconclusive_by_case.items()
        for item in items
    }
    missed_due_to_inconclusive = labeled_tool_keys - found_tool_keys
    missed_due_to_inconclusive &= inconclusive_tool_keys

    return BenchResult(
        class_name=class_name,
        vuln_class=vuln_class,
        case_results=case_results,
        all_findings=all_findings,
        labels=class_labels,
        inconclusive_by_case=inconclusive_by_case,
        metrics=metrics,
        missed_due_to_inconclusive=len(missed_due_to_inconclusive),
    )


def run_full_benchmark(
    *,
    bench_dir: Path | None = None,
    on_case_start: OnCaseStart | None = None,
    on_case_done: OnCaseDone | None = None,
) -> tuple[dict[str, BenchResult], Metrics]:
    """Ejecuta las tres clases y añade una métrica global sobre su unión.

    Los casos de cada clase son disjuntos (prefijos distintos), así que la
    métrica global de combinar todos los hallazgos y etiquetas coincide con
    sumar las métricas por clase; se recalcula con `compute_metrics` en vez
    de sumar a mano para no duplicar esa lógica.
    """
    bench_dir = bench_dir or BENCH
    results: dict[str, BenchResult] = {}
    combined_findings: list[Finding] = []
    combined_labels: dict[str, list[Label]] = {}

    for class_name in CLASS_CONFIG:
        result = run_class_benchmark(
            class_name, bench_dir=bench_dir, on_case_start=on_case_start, on_case_done=on_case_done,
        )
        results[class_name] = result
        combined_findings.extend(result.all_findings)
        combined_labels.update(result.labels)

    global_metrics = compute_metrics(combined_findings, combined_labels)
    return results, global_metrics
