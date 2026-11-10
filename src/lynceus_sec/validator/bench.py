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

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from lynceus_sec.core.labels import load_labels
from lynceus_sec.core.metrics import Metrics, compute_metrics
from lynceus_sec.core.model import Finding, Label, VulnClass
from lynceus_sec.validator.parallel import ParallelContext
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


def _run_cases_sequentially(
    cases: list[Path],
    validate_case: Callable[..., tuple],
    on_case_start: OnCaseStart | None,
    on_case_done: OnCaseDone | None,
) -> list[CaseResult]:
    """Un caso detrás de otro, en orden: el comportamiento de siempre (`--jobs 1`)."""
    case_results: list[CaseResult] = []
    for case_dir in cases:
        case_id = case_dir.name
        if on_case_start is not None:
            on_case_start(case_id)
        try:
            # path_traversal devuelve un tercer elemento (controles positivos,
            # informativos) que bench no usa para las métricas; se ignora.
            result_tuple = validate_case(case_dir)
            result = CaseResult(case_id=case_id, findings=result_tuple[0], inconclusive=result_tuple[1])
        except RunnerError as exc:
            result = CaseResult(case_id=case_id, error=str(exc))
        case_results.append(result)
        if on_case_done is not None:
            on_case_done(result)
    return case_results


def _run_cases_in_parallel(
    cases: list[Path],
    validate_case: Callable[..., tuple],
    on_case_start: OnCaseStart | None,
    on_case_done: OnCaseDone | None,
    jobs: int,
    ctx: ParallelContext,
) -> list[CaseResult]:
    """Hasta `len(cases)` casos "arrancados" a la vez, cada uno en su propio
    hilo coordinador; cada coordinador adquiere el semáforo de `ctx` antes
    de crear nada propio (red/receptor de SSRF) y lo libera al terminar, así
    que nunca hay más de `jobs` casos creando sus propios recursos a la vez.
    Todo contenedor/red que arranque cualquier caso pasa por el pool
    compartido de `ctx`: nunca se crea uno aparte por caso.

    Igual que con `--jobs 1`: un `RunnerError` de un caso se registra y no
    afecta a los demás. Cualquier otra cosa (incluida una interrupción) mata
    todo lo que esté en marcha en `ctx.active` y se propaga, abortando el
    resto exactamente como lo haría hoy un fallo no capturado a mitad del
    bucle secuencial.

    El resultado final se ensambla iterando `cases` en su orden original,
    nunca en el de finalización real: con cualquier `jobs`, el contenido y
    el orden son los mismos. `on_case_start`/`on_case_done` sí pueden llegar
    en orden de finalización real (son solo para progreso en pantalla).
    """
    results_by_id: dict[str, CaseResult] = {}
    lock = threading.Lock()

    def run_one(case_dir: Path) -> None:
        case_id = case_dir.name
        with lock:
            if on_case_start is not None:
                on_case_start(case_id)
        try:
            result_tuple = validate_case(case_dir, jobs=jobs, ctx=ctx)
            result = CaseResult(case_id=case_id, findings=result_tuple[0], inconclusive=result_tuple[1])
        except RunnerError as exc:
            result = CaseResult(case_id=case_id, error=str(exc))
        with lock:
            results_by_id[case_id] = result
            if on_case_done is not None:
                on_case_done(result)

    with ThreadPoolExecutor(max_workers=max(len(cases), 1)) as drivers:
        futures = [drivers.submit(run_one, case_dir) for case_dir in cases]
        try:
            for future in futures:
                future.result()
        except BaseException:
            ctx.active.kill_and_clear()
            raise

    return [results_by_id[case_dir.name] for case_dir in cases]


def run_class_benchmark(
    class_name: str,
    *,
    bench_dir: Path | None = None,
    on_case_start: OnCaseStart | None = None,
    on_case_done: OnCaseDone | None = None,
    jobs: int = 1,
    ctx: ParallelContext | None = None,
) -> BenchResult:
    """Ejecuta la validación dinámica de `class_name` sobre `bench_dir` (por
    defecto `benchmark/cases`). Con `jobs <= 1` (o sin `ctx`), exactamente
    el bucle secuencial de siempre. Con `jobs > 1`, los casos de esta clase
    se reparten entre los hilos coordinadores de `_run_cases_in_parallel`,
    compartiendo el pool y el semáforo de `ctx`."""
    bench_dir = bench_dir or BENCH
    config = CLASS_CONFIG[class_name]
    prefix = config["prefix"]
    vuln_class = config["vuln_class"]
    validate_case = validate_case_for(vuln_class)

    labels_by_case = load_labels(bench_dir)
    cases = sorted(p for p in bench_dir.iterdir() if p.is_dir() and p.name.startswith(prefix))
    class_labels = {case_id: labels for case_id, labels in labels_by_case.items() if case_id.startswith(prefix)}

    if jobs <= 1 or ctx is None:
        case_results = _run_cases_sequentially(cases, validate_case, on_case_start, on_case_done)
    else:
        case_results = _run_cases_in_parallel(cases, validate_case, on_case_start, on_case_done, jobs, ctx)

    return _assemble_bench_result(class_name, vuln_class, case_results, class_labels)


def _assemble_bench_result(
    class_name: str,
    vuln_class: VulnClass,
    case_results: list[CaseResult],
    class_labels: dict[str, list[Label]],
) -> BenchResult:
    all_findings: list[Finding] = []
    inconclusive_by_case: dict[str, list[dict]] = {}
    for result in case_results:
        all_findings.extend(result.findings)
        if result.inconclusive:
            inconclusive_by_case[result.case_id] = result.inconclusive

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
    jobs: int = 1,
) -> tuple[dict[str, BenchResult], Metrics]:
    """Ejecuta las tres clases y añade una métrica global sobre su unión.

    Los casos de cada clase son disjuntos (prefijos distintos), así que la
    métrica global de combinar todos los hallazgos y etiquetas coincide con
    sumar las métricas por clase; se recalcula con `compute_metrics` en vez
    de sumar a mano para no duplicar esa lógica.

    Con `jobs <= 1`, las tres clases se ejecutan una detrás de otra, igual
    que siempre. Con `jobs > 1`, se crea un único `ParallelContext` (un solo
    pool y un solo semáforo de tamaño `jobs` para las tres clases, nunca uno
    aparte por clase) y las tres se lanzan a la vez, cada una en su propio
    hilo coordinador; el resultado se ensambla iterando `CLASS_CONFIG` en su
    orden fijo, no en el de finalización real.
    """
    bench_dir = bench_dir or BENCH
    results: dict[str, BenchResult] = {}
    combined_findings: list[Finding] = []
    combined_labels: dict[str, list[Label]] = {}

    if jobs <= 1:
        for class_name in CLASS_CONFIG:
            result = run_class_benchmark(
                class_name, bench_dir=bench_dir, on_case_start=on_case_start, on_case_done=on_case_done,
            )
            results[class_name] = result
    else:
        ctx = ParallelContext.create(jobs)
        try:
            with ThreadPoolExecutor(max_workers=len(CLASS_CONFIG)) as class_drivers:
                futures = {
                    class_name: class_drivers.submit(
                        run_class_benchmark, class_name, bench_dir=bench_dir,
                        on_case_start=on_case_start, on_case_done=on_case_done, jobs=jobs, ctx=ctx,
                    )
                    for class_name in CLASS_CONFIG
                }
                try:
                    for class_name in CLASS_CONFIG:
                        results[class_name] = futures[class_name].result()
                except BaseException:
                    ctx.active.kill_and_clear()
                    raise
        finally:
            ctx.shutdown()

    for class_name in CLASS_CONFIG:
        combined_findings.extend(results[class_name].all_findings)
        combined_labels.update(results[class_name].labels)

    global_metrics = compute_metrics(combined_findings, combined_labels)
    return results, global_metrics
