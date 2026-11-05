"""CLI `lynceus`: valida dinámicamente servidores MCP y muestra/exporta los resultados.

Exit codes de `scan`: 0 sin hallazgos confirmados, 1 con hallazgos
confirmados, 2 error (argumentos inválidos, carpeta/objetivo inválido, o
fallo del entorno de validación).

Exit codes de `build`: 0 imagen objetivo lista (nueva o reaprovechada), 2
error (argumentos inválidos o fallo resolviendo/construyendo).
"""

from __future__ import annotations

import json as jsonlib
import time
from datetime import date
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import typer

from lynceus_sec.cli_env import collect_environment_info
from lynceus_sec.cli_html import build_html_report
from lynceus_sec.cli_render import (
    ScanSummary,
    is_plain_mode,
    make_console,
    render_build_result,
    render_capabilities,
    render_clean_images,
    render_clean_plan,
    render_clean_result,
    render_findings_table,
    render_fs_root,
    render_header,
    render_inconclusive,
    render_metrics_table,
    render_positive_controls,
    render_report_paths,
    render_sandbox_status,
    render_summary,
    render_target_image,
    run_with_progress,
)
from lynceus_sec.core.metrics import compute_metrics
from lynceus_sec.core.model import Finding, Label
from lynceus_sec.report import CAPABILITY_EXPLANATION, CLASS_LABELS, group_findings
from lynceus_sec.validator import build as build_mod
from lynceus_sec.validator import clean as clean_mod
from lynceus_sec.validator.bench import (
    CLASS_CONFIG,
    run_class_benchmark,
    validate_case_for,
)
from lynceus_sec.validator.runner import (
    DEFAULT_ENTRY,
    DEFAULT_FS_ROOT,
    TARGET_PYTHON,
    RunnerError,
    _docker_responding,
    _image_exists,
)

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


def _validate_entry(target: Path, entry: str, console) -> str:
    """--entry debe ser una ruta relativa a `target`, sin componentes '..' ni
    absoluta, apuntar a un fichero existente dentro de la carpeta y terminar
    en .py."""
    entry_path = Path(entry)
    if entry_path.is_absolute() or ".." in entry_path.parts:
        console.print(f"Error: --entry {entry!r} debe ser relativo a la carpeta, sin rutas absolutas ni '..'.")
        raise typer.Exit(2)
    full_path = target / entry_path
    if not full_path.is_file():
        console.print(f"Error: {target} no contiene el punto de entrada {entry!r} (o no es un fichero).")
        raise typer.Exit(2)
    if full_path.suffix != ".py":
        console.print(f"Error: --entry {entry!r} debe ser un fichero .py.")
        raise typer.Exit(2)
    return entry


def _validate_pythonpaths(target: Path, pythonpaths: list[str], console) -> list[str]:
    """Cada --pythonpath debe ser una ruta relativa a `target`, sin
    componentes '..' ni absoluta, y apuntar a una carpeta existente dentro
    de la carpeta analizada."""
    for raw in pythonpaths:
        path = Path(raw)
        if path.is_absolute() or ".." in path.parts:
            console.print(f"Error: --pythonpath {raw!r} debe ser relativo a la carpeta, sin rutas absolutas ni '..'.")
            raise typer.Exit(2)
        if not (target / path).is_dir():
            console.print(f"Error: --pythonpath {raw!r} no es una carpeta dentro de {target}.")
            raise typer.Exit(2)
    return pythonpaths


def _validate_requirements_path(target: Path, requirements: str, console) -> str:
    """--requirements debe ser relativo a `target`, sin rutas absolutas ni
    '..', y apuntar a un fichero existente dentro de la carpeta (mismo
    patrón que --entry en `scan`)."""
    req_path = Path(requirements)
    if req_path.is_absolute() or ".." in req_path.parts:
        console.print(f"Error: --requirements {requirements!r} debe ser relativo a la carpeta, sin rutas absolutas ni '..'.")
        raise typer.Exit(2)
    full_path = target / req_path
    if not full_path.is_file():
        console.print(f"Error: {target} no contiene el fichero de requisitos {requirements!r} (o no es un fichero).")
        raise typer.Exit(2)
    return requirements


def _validate_target_image(value: str | None, console) -> str | None:
    """--image debe tener la forma `lynceus-target:<12 hex>` (ver `validator.build`)
    y existir ya en local; si no se da (`None`), `scan` se comporta como hoy."""
    if value is None:
        return None
    if not build_mod.TARGET_IMAGE_RE.fullmatch(value):
        console.print(
            f"Error: --image {value!r} debe tener la forma 'lynceus-target:' "
            "seguido de 12 caracteres hexadecimales."
        )
        raise typer.Exit(2)
    if not _docker_responding():
        console.print("Error: Docker no responde: ¿está en marcha?")
        raise typer.Exit(2)
    if not _image_exists(value):
        console.print(f"Error: la imagen {value!r} no existe en local; constrúyela con 'lynceus build'.")
        raise typer.Exit(2)
    return value


def _validate_resolve_date(value: str | None, console) -> str | None:
    if value is None:
        return None
    try:
        date.fromisoformat(value)
    except ValueError:
        console.print(f"Error: --resolve-date {value!r} debe tener el formato AAAA-MM-DD.")
        raise typer.Exit(2)
    return value


def _serialize_capability_confirmation(confirmation: dict) -> dict:
    return {
        "technique": confirmation["technique"],
        "payload": confirmation["payload"],
        "evidence": confirmation["evidence"],
        "reproduction": [call.model_dump() for call in confirmation.get("reproduction") or []],
    }


def _serialize_capabilities(capabilities_by_class: dict[str, list[dict]]) -> dict[str, list[dict]]:
    return {
        class_name: [
            {
                "tool": item["tool"],
                "parameter": item.get("parameter"),
                "probe": _serialize_capability_confirmation(item["probe"]) if item.get("probe") else None,
                "confirmations": [
                    _serialize_capability_confirmation(confirmation)
                    for confirmation in item.get("confirmations", [])
                ],
                "bypassable_filter": item.get("bypassable_filter", False),
                "blocked_techniques": item.get("blocked_techniques", []),
            }
            for item in items
        ]
        for class_name, items in capabilities_by_class.items()
    }


def _build_json_payload(
    *,
    target: str,
    classes: list[str],
    fs_root: str,
    findings: list[Finding],
    inconclusive_by_class: dict[str, list[dict]],
    positive_controls_by_class: dict[str, list[dict]],
    capabilities_by_class: dict[str, list[dict]],
    elapsed_seconds: float,
    environment,
) -> dict:
    groups = group_findings(findings)
    return {
        "schema_version": 2,
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
        "capabilities": _serialize_capabilities(capabilities_by_class),
        "capabilities_note": CAPABILITY_EXPLANATION,
        "environment": {
            "lynceus_version": environment.lynceus_version,
            "sandbox_image": environment.sandbox_image,
            "sandbox_image_id": environment.sandbox_image_id,
            "base_image_ref": environment.base_image_ref,
            "declared_python_version": environment.declared_python_version,
            "declared_mcp_version": environment.declared_mcp_version,
            "target_image": environment.target_image,
            "target_image_id": environment.target_image_id,
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
    entry: str = typer.Option(
        DEFAULT_ENTRY, "--entry",
        help="Punto de entrada .py a arrancar, relativo a la carpeta analizada (por defecto server.py).",
    ),
    pythonpath: list[str] = typer.Option(  # noqa: B008 - patrón estándar de typer
        [], "--pythonpath",
        help="Carpeta dentro del objetivo a añadir a PYTHONPATH (repetible).",
    ),
    image: str | None = typer.Option(
        None, "--image",
        help="Imagen 'lynceus-target:<12 hex>' (de 'lynceus build') en la que arrancar el servidor; "
        "por defecto se usa el sandbox y su propio intérprete.",
    ),
    plain: bool = typer.Option(False, "--plain", help="Salida de texto plano, sin colores ni emojis."),
) -> None:
    """Valida dinámicamente una carpeta con server.py frente a las clases indicadas."""
    plain_mode = is_plain_mode(plain_flag=plain)
    console = make_console(plain=plain_mode)
    render_header(console, version=_lynceus_version(), plain=plain_mode)

    normalized_classes = _normalize_classes(classes, console)
    fs_root = _validate_fs_root(fs_root, console)
    image = _validate_target_image(image, console)

    if not target.is_dir():
        console.print(f"Error: {target} no es una carpeta.")
        raise typer.Exit(2)

    entry = _validate_entry(target, entry, console)
    pythonpath = _validate_pythonpaths(target, pythonpath, console)

    if "path_traversal" in normalized_classes:
        render_fs_root(console, fs_root, plain=plain_mode)

    # Solo con --image se añaden `image`/`server_python`: sin él, las
    # llamadas quedan idénticas a las de siempre (mismos defaults de cada
    # validate_case).
    image_kwargs: dict[str, str] = {}
    if image is not None:
        image_kwargs = {"image": image, "server_python": TARGET_PYTHON}

    start = time.monotonic()
    all_findings: list[Finding] = []
    inconclusive_by_class: dict[str, list[dict]] = {}
    positive_controls_by_class: dict[str, list[dict]] = {}
    capabilities_by_class: dict[str, list[dict]] = {}
    had_error = False

    for class_name in normalized_classes:
        vuln_class = CLASS_CONFIG[class_name]["vuln_class"]
        validate_case = validate_case_for(vuln_class)
        render_sandbox_status(console, class_name=class_name, network=_network_for(class_name), plain=plain_mode)
        try:
            if class_name == "path_traversal":
                result = run_with_progress(
                    console, class_name=class_name, plain=plain_mode,
                    fn=lambda validate_case=validate_case: validate_case(
                        target, fs_root=fs_root, entry=entry, pythonpath=pythonpath, **image_kwargs,
                    ),
                )
            else:
                result = run_with_progress(
                    console, class_name=class_name, plain=plain_mode,
                    fn=lambda validate_case=validate_case: validate_case(
                        target, entry=entry, pythonpath=pythonpath, **image_kwargs,
                    ),
                )
        except RunnerError as exc:
            label = CLASS_LABELS.get(class_name, class_name)
            console.print(f"Error ejecutando la validación de {label}: {exc}")
            had_error = True
            continue
        findings, inconclusive, *rest = result
        all_findings.extend(findings)
        if inconclusive:
            inconclusive_by_class[class_name] = inconclusive
        # El tercer elemento es específico de cada clase: controles positivos
        # (path_traversal) o capacidades de ejecución de comandos (cmdi).
        if class_name == "path_traversal" and rest and rest[0]:
            positive_controls_by_class[class_name] = rest[0]
        elif class_name == "command_injection" and rest and rest[0]:
            capabilities_by_class[class_name] = rest[0]

    elapsed = time.monotonic() - start

    if had_error:
        raise typer.Exit(2)

    render_findings_table(console, all_findings, plain=plain_mode)
    render_inconclusive(console, inconclusive_by_class, plain=plain_mode)
    render_capabilities(console, capabilities_by_class, plain=plain_mode)
    render_positive_controls(console, positive_controls_by_class, plain=plain_mode)

    summary = ScanSummary(
        vulnerabilities=len(group_findings(all_findings)),
        techniques=len(all_findings),
        inconclusive=sum(len(v) for v in inconclusive_by_class.values()),
        elapsed_seconds=elapsed,
    )
    render_summary(console, summary, plain=plain_mode)

    environment = collect_environment_info(target_image=image)
    render_target_image(
        console, image=environment.target_image, image_id=environment.target_image_id, plain=plain_mode,
    )

    if json_path is not None:
        payload = _build_json_payload(
            target=str(target), classes=normalized_classes, fs_root=fs_root, findings=all_findings,
            inconclusive_by_class=inconclusive_by_class, positive_controls_by_class=positive_controls_by_class,
            capabilities_by_class=capabilities_by_class, elapsed_seconds=elapsed, environment=environment,
        )
        json_path.write_text(jsonlib.dumps(payload, indent=2, ensure_ascii=False))

    if report_path is not None:
        html_text = build_html_report(
            target=str(target), classes=normalized_classes, fs_root=fs_root, findings=all_findings,
            inconclusive_by_class=inconclusive_by_class, positive_controls_by_class=positive_controls_by_class,
            capabilities_by_class=capabilities_by_class, elapsed_seconds=elapsed, environment=environment,
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
def build(
    target: Path = typer.Argument(  # noqa: B008 - patrón estándar de typer
        ..., help="Carpeta del servidor objetivo (su código no se modifica)."
    ),
    requirements: str = typer.Option(
        ..., "--requirements", help="Ruta relativa dentro de la carpeta al fichero de requisitos a resolver.",
    ),
    resolve_date: str | None = typer.Option(
        None, "--resolve-date",
        help="Fecha AAAA-MM-DD: excluye versiones publicadas después (uv --exclude-newer).",
    ),
    plain: bool = typer.Option(False, "--plain", help="Salida de texto plano, sin colores ni emojis."),
) -> None:
    """Resuelve las dependencias de la carpeta objetivo en un contenedor aparte
    y construye la imagen que las instala, sin tocar el entorno del harness."""
    plain_mode = is_plain_mode(plain_flag=plain)
    console = make_console(plain=plain_mode)
    render_header(console, version=_lynceus_version(), plain=plain_mode)

    if not target.is_dir():
        console.print(f"Error: {target} no es una carpeta.")
        raise typer.Exit(2)

    requirements = _validate_requirements_path(target, requirements, console)
    resolve_date = _validate_resolve_date(resolve_date, console)

    try:
        result = run_with_progress(
            console, class_name="build", plain=plain_mode,
            fn=lambda: build_mod.run_build(target, requirements, resolve_date=resolve_date),
        )
    except build_mod.BuildError as exc:
        console.print(f"Error construyendo la imagen objetivo: {exc}")
        raise typer.Exit(2)

    render_build_result(console, result, plain=plain_mode)
    raise typer.Exit(0)


@app.command()
def clean(
    yes: bool = typer.Option(
        False, "--yes", help="Borra las imágenes y la caché de build en vez de solo listarlas.",
    ),
    keep: list[str] = typer.Option(  # noqa: B008 - patrón estándar de typer
        [], "--keep", help="Etiqueta 'lynceus-target:<hash>' a conservar (repetible).",
    ),
    plain: bool = typer.Option(False, "--plain", help="Salida de texto plano, sin colores ni emojis."),
) -> None:
    """Lista las imágenes lynceus-target:* locales (con --yes, las borra junto
    con la caché de construcción de Lynceus). Nunca toca lynceus-sandbox ni
    lynceus-resolver ni ninguna otra imagen."""
    plain_mode = is_plain_mode(plain_flag=plain)
    console = make_console(plain=plain_mode)
    render_header(console, version=_lynceus_version(), plain=plain_mode)

    # Toda validación va antes que cualquier borrado: con --yes, ni una
    # imagen ni la caché se tocan hasta que Docker responde y la ruta de la
    # caché es segura de borrar.
    try:
        clean_mod.ensure_docker_responding()
        cache_path = clean_mod.ensure_cache_removal_is_safe() if yes else None
    except clean_mod.CleanError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(2)

    images = clean_mod.list_target_images()
    render_clean_images(console, images, plain=plain_mode)

    if not yes:
        raise typer.Exit(0)

    to_remove = [image.tag for image in images if image.tag not in keep]
    kept = [image.tag for image in images if image.tag in keep]
    render_clean_plan(console, to_remove=to_remove, kept=kept, cache_path=cache_path, plain=plain_mode)

    removed, failed = clean_mod.remove_images(to_remove)
    removed_cache = clean_mod.remove_cache_dir()

    render_clean_result(
        console, removed=removed, kept=kept, failed=failed, cache_path=removed_cache, plain=plain_mode,
    )
    raise typer.Exit(0)


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
