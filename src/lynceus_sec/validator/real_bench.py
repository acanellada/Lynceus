"""Ejecuta la validación dinámica sobre la suite de servidores reales
(`benchmark/real/*.toml`, ver `real_manifest`): por cada versión de cada
manifiesto, obtiene su código (`real_source`), construye su imagen
(`validator.build`) y valida solo la clase del manifiesto (`validator.bench`),
comparando los hallazgos con los esperados por `(tool, parameter)`.

Mismo patrón que `validator.bench` para `--jobs`: con `jobs <= 1`, una
versión detrás de otra; con `jobs > 1`, un único `ParallelContext` compartido
por todas las versiones (nunca uno aparte por versión), con hasta `jobs`
hilos coordinadores. La construcción de la imagen (`lynceus build`) no pasa
por ese pool (no arranca el sandbox de validación, solo contenedores de
resolución/descarga de `validator.build`, ya aislados entre sí por su propio
nombre de contenedor aleatorio); el pool solo reparte la validación dinámica.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from lynceus_sec.core.metrics import ClassMetrics, Metrics, _ratio
from lynceus_sec.core.model import VulnClass
from lynceus_sec.validator import build as build_mod
from lynceus_sec.validator import real_source
from lynceus_sec.validator.bench import validate_case_for
from lynceus_sec.validator.parallel import ParallelContext
from lynceus_sec.validator.real_manifest import RealManifest, RealVersion
from lynceus_sec.validator.runner import DEFAULT_FS_ROOT, TARGET_PYTHON, RunnerError


@dataclass
class RealVersionResult:
    manifest_id: str
    cve: str | None
    vuln_class: VulnClass
    label: str
    expected: list[tuple[str, str]]
    found: list[tuple[str, str]] = field(default_factory=list)
    inconclusive: list[dict] = field(default_factory=list)
    image_tag: str | None = None
    error: str | None = None
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def case_id(self) -> str:
        return f"{self.manifest_id}:{self.label}"


@dataclass
class RealBenchResult:
    version_results: list[RealVersionResult]
    metrics: Metrics
    inconclusive_by_class: dict[str, int]
    inconclusive_by_case: dict[str, int]
    errored: list[RealVersionResult] = field(default_factory=list)


OnCaseStart = Callable[[str], None]
OnCaseDone = Callable[[RealVersionResult], None]


def compare_expected(
    expected: list[tuple[str, str]], found: list[tuple[str, str]]
) -> tuple[int, int, int]:
    """TP/FP/FN por coincidencia exacta de `(tool, parameter)`, deduplicando
    ambas listas antes de comparar (mismo criterio que `core.metrics`, pero
    con el parámetro como parte de la clave: aquí dos hallazgos de la misma
    tool con distinto parámetro son vulnerabilidades distintas)."""
    expected_keys = set(expected)
    found_keys = set(found)
    tp = len(expected_keys & found_keys)
    fp = len(found_keys - expected_keys)
    fn = len(expected_keys - found_keys)
    return tp, fp, fn


def _run_one_version(
    manifest: RealManifest,
    version: RealVersion,
    *,
    jobs: int,
    ctx: ParallelContext | None,
    cache_root: Path | None,
) -> RealVersionResult:
    expected = [(item.tool, item.parameter) for item in version.expected]
    result = RealVersionResult(
        manifest_id=manifest.id, cve=manifest.cve, vuln_class=manifest.vuln_class,
        label=version.label, expected=expected,
    )

    try:
        repo_dir = real_source.clone_repo_once(manifest.repo, cache_root=cache_root)
        workdir = real_source.prepare_version_source(
            manifest.id, version.label, manifest.repo, version.commit, cache_root=cache_root,
        )
        resolve_date = version.resolve_date or real_source.commit_date(repo_dir, version.commit)
        target_dir = workdir / manifest.subdir if manifest.subdir else workdir

        build_result = build_mod.run_build(target_dir, manifest.requirements, resolve_date=resolve_date)
        result.image_tag = build_result.tag

        validate_case = validate_case_for(manifest.vuln_class)
        kwargs: dict = {
            "image": build_result.tag,
            "server_python": TARGET_PYTHON,
            "entry": manifest.entry,
            "pythonpath": manifest.pythonpath,
        }
        if manifest.vuln_class is VulnClass.PATH_TRAVERSAL:
            kwargs["fs_root"] = manifest.fs_root or DEFAULT_FS_ROOT
        if jobs > 1 and ctx is not None:
            kwargs["jobs"] = jobs
            kwargs["ctx"] = ctx

        findings, inconclusive, *_rest = validate_case(target_dir, **kwargs)
        result.found = [(finding.tool, finding.parameter) for finding in findings]
        result.inconclusive = inconclusive
    except (real_source.RealSourceError, build_mod.BuildError, RunnerError) as exc:
        # Un error de entorno (clonado, build o scan) no dice nada sobre si
        # Lynceus habría encontrado lo esperado: no se pudo ni intentar. Se
        # deja sin tp/fp/fn (quedan en 0, su valor por defecto) en vez de
        # contarlo como un falso negativo; `_assemble_real_result` lo excluye
        # también de las métricas agregadas y lo lista aparte.
        result.error = str(exc)
        return result

    result.tp, result.fp, result.fn = compare_expected(result.expected, result.found)
    return result


def _run_versions_sequentially(
    units: list[tuple[RealManifest, RealVersion]],
    on_case_start: OnCaseStart | None,
    on_case_done: OnCaseDone | None,
    cache_root: Path | None,
) -> list[RealVersionResult]:
    results: list[RealVersionResult] = []
    for manifest, version in units:
        case_id = f"{manifest.id}:{version.label}"
        if on_case_start is not None:
            on_case_start(case_id)
        result = _run_one_version(manifest, version, jobs=1, ctx=None, cache_root=cache_root)
        results.append(result)
        if on_case_done is not None:
            on_case_done(result)
    return results


def _run_versions_in_parallel(
    units: list[tuple[RealManifest, RealVersion]],
    on_case_start: OnCaseStart | None,
    on_case_done: OnCaseDone | None,
    jobs: int,
    ctx: ParallelContext,
    cache_root: Path | None,
) -> list[RealVersionResult]:
    results_by_id: dict[str, RealVersionResult] = {}
    lock = threading.Lock()

    def run_one(manifest: RealManifest, version: RealVersion) -> None:
        case_id = f"{manifest.id}:{version.label}"
        with lock:
            if on_case_start is not None:
                on_case_start(case_id)
        result = _run_one_version(manifest, version, jobs=jobs, ctx=ctx, cache_root=cache_root)
        with lock:
            results_by_id[case_id] = result
            if on_case_done is not None:
                on_case_done(result)

    with ThreadPoolExecutor(max_workers=max(len(units), 1)) as drivers:
        futures = [drivers.submit(run_one, manifest, version) for manifest, version in units]
        try:
            for future in futures:
                future.result()
        except BaseException:
            ctx.active.kill_and_clear()
            raise

    return [results_by_id[f"{manifest.id}:{version.label}"] for manifest, version in units]


def _assemble_real_result(version_results: list[RealVersionResult]) -> RealBenchResult:
    tp_by_class = dict.fromkeys(VulnClass, 0)
    fp_by_class = dict.fromkeys(VulnClass, 0)
    fn_by_class = dict.fromkeys(VulnClass, 0)
    inconclusive_by_class: dict[str, int] = {}
    inconclusive_by_case: dict[str, int] = {}
    errored: list[RealVersionResult] = []

    for result in version_results:
        if result.error is not None:
            # No se pudo ni intentar: fuera de TP/FP/FN (por clase y global),
            # se lista aparte en vez de contarse como un falso negativo.
            errored.append(result)
            continue
        tp_by_class[result.vuln_class] += result.tp
        fp_by_class[result.vuln_class] += result.fp
        fn_by_class[result.vuln_class] += result.fn
        if result.inconclusive:
            class_name = result.vuln_class.value
            inconclusive_by_class[class_name] = inconclusive_by_class.get(class_name, 0) + len(result.inconclusive)
            inconclusive_by_case[result.case_id] = len(result.inconclusive)

    by_class = {
        vuln_class: ClassMetrics(
            tp=tp_by_class[vuln_class], fp=fp_by_class[vuln_class], fn=fn_by_class[vuln_class],
            precision=_ratio(tp_by_class[vuln_class], tp_by_class[vuln_class] + fp_by_class[vuln_class]),
            recall=_ratio(tp_by_class[vuln_class], tp_by_class[vuln_class] + fn_by_class[vuln_class]),
        )
        for vuln_class in VulnClass
    }
    tp, fp, fn = sum(tp_by_class.values()), sum(fp_by_class.values()), sum(fn_by_class.values())
    metrics = Metrics(
        tp=tp, fp=fp, fn=fn,
        precision=_ratio(tp, tp + fp), recall=_ratio(tp, tp + fn),
        by_class=by_class,
    )

    return RealBenchResult(
        version_results=version_results,
        metrics=metrics,
        inconclusive_by_class=inconclusive_by_class,
        inconclusive_by_case=inconclusive_by_case,
        errored=errored,
    )


def run_real_benchmark(
    manifests: list[RealManifest],
    *,
    on_case_start: OnCaseStart | None = None,
    on_case_done: OnCaseDone | None = None,
    jobs: int = 1,
    cache_root: Path | None = None,
) -> RealBenchResult:
    units = [(manifest, version) for manifest in manifests for version in manifest.versions]

    if jobs <= 1:
        version_results = _run_versions_sequentially(units, on_case_start, on_case_done, cache_root)
    else:
        ctx = ParallelContext.create(jobs)
        try:
            version_results = _run_versions_in_parallel(units, on_case_start, on_case_done, jobs, ctx, cache_root)
        finally:
            ctx.shutdown()

    return _assemble_real_result(version_results)
