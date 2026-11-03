"""CLI `lynceus`: valida dinámicamente servidores MCP y muestra/exporta los resultados.

Exit codes de `scan`: 0 sin hallazgos confirmados, 1 con hallazgos
confirmados, 2 error (argumentos inválidos, carpeta/objetivo inválido, o
fallo del entorno de validación).
"""

from __future__ import annotations

import json as jsonlib
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import typer

from lynceus_sec.cli_env import collect_environment_info
from lynceus_sec.cli_html import build_html_report
from lynceus_sec.cli_render import (
    ScanSummary,
    is_plain_mode,
    make_console,
    render_findings_table,
    render_fs_root,
    render_header,
    render_inconclusive,
    render_metrics_table,
    render_positive_controls,
    render_report_paths,
    render_sandbox_status,
    render_summary,
    run_with_progress,
)
from lynceus_sec.core.metrics import compute_metrics
from lynceus_sec.core.model import Finding, Label
from lynceus_sec.report import CLASS_LABELS, group_findings
from lynceus_sec.validator.bench import (
    CLASS_CONFIG,
    run_class_benchmark,
    validate_case_for,
)
from lynceus_sec.validator.runner import DEFAULT_FS_ROOT, RunnerError

app = typer.Typer(
    name="lynceus",
    help="Validador de seguridad para servidores MCP (Model Context Protocol).",
    no_args_is_help=True,
    add_completion=False,
)

ALL_CLASSES = list(CLASS_CONFIG)


def _lynceus_version() -> str:
    try:
        return version("lynceus-sec")
    except PackageNotFoundError:
        return "0.0.0"


def _normalize_classes(classes: list[str], console) -> list[str]:
    normalized = [c.lower() for c in classes]
    unknown = sorted(set(normalized) - set(CLASS_CONFIG))
    if unknown:
        console.print(
            f"Clase desconocida: {', '.join(unknown)}. Opciones válidas: {', '.join(ALL_CLASSES)}."
        )
        raise typer.Exit(2)
    return normalized


def _network_for(class_name: str) -> str:
    return "internal" if class_name == "ssrf" else "none"


def _validate_fs_root(value: str, console) -> str:
    """--fs-root debe ser una ruta absoluta bajo /tmp (el resto del sistema de
    ficheros del sandbox es de solo lectura), sin componentes ".." y distinta
    de /tmp mismo (ahí viven la carpeta aparte y la carpeta hermana de los
    canarios, y el límite necesita ser una subcarpeta propia)."""
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        console.print(f"Error: --fs-root {value!r} debe ser una ruta absoluta, sin componentes '..'.")
        raise typer.Exit(2)
    try:
        path.relative_to("/tmp")
    except ValueError:
        console.print(f"Error: --fs-root {value!r} debe estar bajo /tmp (el resto del sandbox es de solo lectura).")
        raise typer.Exit(2)
    if path == Path("/tmp"):
        console.print("Error: --fs-root no puede ser /tmp mismo; usa una subcarpeta, p.ej. /tmp/mi-limite.")
        raise typer.Exit(2)
    return str(path)


def _build_json_payload(
    *,
    target: str,
    classes: list[str],
    fs_root: str,
    findings: list[Finding],
    inconclusive_by_class: dict[str, list[dict]],
    positive_controls_by_class: dict[str, list[dict]],
    elapsed_seconds: float,
    environment,
) -> dict:
    groups = group_findings(findings)
    return {
        "schema_version": 1,
        "target": target,
        "classes": classes,
        "fs_root": fs_root,
        "summary": {
            "vulnerabilities_confirmed": len(groups),
            "techniques_confirmed": len(findings),
            "inconclusive": sum(len(v) for v in inconclusive_by_class.values()),
            "elapsed_seconds": elapsed_seconds,
        },
        "vulnerabilities": [
            {
                "case": g.case,
                "tool": g.tool,
                "parameter": g.parameter,
                "vuln_class": g.vuln_class.value,
                "severity": g.severity,
                "techniques": g.techniques,
                "confirmations": [
                    {
                        "technique": f.technique,
                        "rule_id": f.rule_id,
                        "payload": f.payload,
                        "evidence": f.evidence,
                        "reproduction": [call.model_dump() for call in (f.reproduction or [])],
                    }
                    for f in g.findings
                ],
            }
            for g in groups
        ],
        "inconclusive": inconclusive_by_class,
        "positive_controls": positive_controls_by_class,
        "environment": {
            "lynceus_version": environment.lynceus_version,
            "sandbox_image": environment.sandbox_image,
            "sandbox_image_id": environment.sandbox_image_id,
            "base_image_ref": environment.base_image_ref,
            "declared_python_version": environment.declared_python_version,
            "declared_mcp_version": environment.declared_mcp_version,
        },
    }


@app.command()
def scan(
    target: Path = typer.Argument(  # noqa: B008 - patrón estándar de typer
        ..., help="Carpeta con server.py a analizar (mismo formato que un caso del benchmark)."
    ),
    classes: list[str] = typer.Option(  # noqa: B008 - patrón estándar de typer
        ALL_CLASSES, "--classes", help="Clases a validar (repetible).", case_sensitive=False,
    ),
    json_path: Path | None = typer.Option(None, "--json", help="Ruta donde escribir el informe JSON."),  # noqa: B008
    report_path: Path | None = typer.Option(None, "--report", help="Ruta donde escribir el informe HTML."),  # noqa: B008
    fs_root: str = typer.Option(
        DEFAULT_FS_ROOT, "--fs-root",
        help="Límite de sistema de ficheros del servidor analizado (HOME dentro del sandbox); "
        "ruta absoluta bajo /tmp.",
    ),
    plain: bool = typer.Option(False, "--plain", help="Salida de texto plano, sin colores ni emojis."),
) -> None:
    """Valida dinámicamente una carpeta con server.py frente a las clases indicadas."""
    plain_mode = is_plain_mode(plain_flag=plain)
    console = make_console(plain=plain_mode)
    render_header(console, version=_lynceus_version(), plain=plain_mode)

    normalized_classes = _normalize_classes(classes, console)
    fs_root = _validate_fs_root(fs_root, console)

    if not target.is_dir():
        console.print(f"Error: {target} no es una carpeta.")
        raise typer.Exit(2)
    if not (target / "server.py").is_file():
        console.print(f"Error: {target} no contiene server.py.")
        raise typer.Exit(2)

    if "path_traversal" in normalized_classes:
        render_fs_root(console, fs_root, plain=plain_mode)

    start = time.monotonic()
    all_findings: list[Finding] = []
    inconclusive_by_class: dict[str, list[dict]] = {}
    positive_controls_by_class: dict[str, list[dict]] = {}
    had_error = False

    for class_name in normalized_classes:
        vuln_class = CLASS_CONFIG[class_name]["vuln_class"]
        validate_case = validate_case_for(vuln_class)
        render_sandbox_status(console, class_name=class_name, network=_network_for(class_name), plain=plain_mode)
        try:
            if class_name == "path_traversal":
                result = run_with_progress(
                    console, class_name=class_name, plain=plain_mode,
                    fn=lambda validate_case=validate_case: validate_case(target, fs_root=fs_root),
                )
            else:
                result = run_with_progress(
                    console, class_name=class_name, plain=plain_mode,
                    fn=lambda validate_case=validate_case: validate_case(target),
                )
        except RunnerError as exc:
            label = CLASS_LABELS.get(class_name, class_name)
            console.print(f"Error ejecutando la validación de {label}: {exc}")
            had_error = True
            continue
        findings, inconclusive, *rest = result
        positive_controls = rest[0] if rest else []
        all_findings.extend(findings)
        if inconclusive:
            inconclusive_by_class[class_name] = inconclusive
        if positive_controls:
            positive_controls_by_class[class_name] = positive_controls

    elapsed = time.monotonic() - start

    if had_error:
        raise typer.Exit(2)

    render_findings_table(console, all_findings, plain=plain_mode)
    render_inconclusive(console, inconclusive_by_class, plain=plain_mode)
    render_positive_controls(console, positive_controls_by_class, plain=plain_mode)

    summary = ScanSummary(
        vulnerabilities=len(group_findings(all_findings)),
        techniques=len(all_findings),
        inconclusive=sum(len(v) for v in inconclusive_by_class.values()),
        elapsed_seconds=elapsed,
    )
    render_summary(console, summary, plain=plain_mode)

    environment = collect_environment_info()

    if json_path is not None:
        payload = _build_json_payload(
            target=str(target), classes=normalized_classes, fs_root=fs_root, findings=all_findings,
            inconclusive_by_class=inconclusive_by_class, positive_controls_by_class=positive_controls_by_class,
            elapsed_seconds=elapsed, environment=environment,
        )
        json_path.write_text(jsonlib.dumps(payload, indent=2, ensure_ascii=False))

    if report_path is not None:
        html_text = build_html_report(
            target=str(target), classes=normalized_classes, fs_root=fs_root, findings=all_findings,
            inconclusive_by_class=inconclusive_by_class, positive_controls_by_class=positive_controls_by_class,
            elapsed_seconds=elapsed, environment=environment,
        )
        report_path.write_text(html_text)

    render_report_paths(
        console,
        json_path=str(json_path) if json_path is not None else None,
        report_path=str(report_path) if report_path is not None else None,
        plain=plain_mode,
    )

    raise typer.Exit(1 if all_findings else 0)


@app.command()
def bench(
    classes: list[str] = typer.Option(  # noqa: B008 - patrón estándar de typer
        ALL_CLASSES, "--classes", help="Clases a incluir (repetible).", case_sensitive=False,
    ),
    plain: bool = typer.Option(False, "--plain", help="Salida de texto plano, sin colores ni emojis."),
) -> None:
    """Ejecuta la validación dinámica sobre benchmark/cases y muestra las métricas por clase y global."""
    plain_mode = is_plain_mode(plain_flag=plain)
    console = make_console(plain=plain_mode)
    render_header(console, version=_lynceus_version(), plain=plain_mode)

    normalized_classes = _normalize_classes(classes, console)

    combined_findings: list[Finding] = []
    combined_labels: dict[str, list[Label]] = {}
    rows = []

    for class_name in normalized_classes:
        render_sandbox_status(console, class_name=class_name, network=_network_for(class_name), plain=plain_mode)
        result = run_with_progress(
            console, class_name=class_name, plain=plain_mode,
            fn=lambda class_name=class_name: run_class_benchmark(class_name),
        )
        combined_findings.extend(result.all_findings)
        combined_labels.update(result.labels)
        rows.append((CLASS_LABELS.get(class_name, class_name), result.metrics.by_class[result.vuln_class]))

    global_metrics = compute_metrics(combined_findings, combined_labels)
    rows.append(("Global", global_metrics))
    render_metrics_table(console, rows, plain=plain_mode)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
