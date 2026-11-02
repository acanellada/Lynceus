"""Render de terminal para `lynceus`: panel ámbar, progreso por clase, tabla
de hallazgos y resumen final.

Todo texto que venga del servidor analizado (nombres de tool, mensajes,
evidencia) se trata como no confiable: se sanea (quita secuencias de escape
ANSI y caracteres de control) y se envuelve siempre en `rich.text.Text`, que
muestra el texto literal y nunca interpreta su contenido como markup de rich.
Nunca se interpola ese texto dentro de una cadena de markup.
"""

from __future__ import annotations

import os
import re
import sys
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TypeVar

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from lynceus_sec.core.metrics import ClassMetrics
from lynceus_sec.core.model import Finding
from lynceus_sec.report import (
    CLASS_LABELS,
    SEVERITY_LABELS,
    SEVERITY_NOTE,
    format_reproduction,
    group_findings,
)

AMBER = "#b9770e"
AMBER_BRIGHT = "#f0a500"
GOLD = "#d4a017"
RED = "#c62828"
YELLOW = "#f1c40f"
GREEN = "#2e7d32"

_ANSI_RE = re.compile(r"\x1b(?:\[[0-9;?]*[a-zA-Z]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-_])")
_CONTROL_RE = re.compile(r"[\x00-\x09\x0b-\x1f\x7f]")


def sanitize_untrusted(text: str | None) -> str:
    """Quita secuencias de escape ANSI y caracteres de control de texto no confiable."""
    if not text:
        return ""
    text = _ANSI_RE.sub("", text)
    text = _CONTROL_RE.sub(" ", text)
    return text


def is_plain_mode(*, plain_flag: bool, stream=None) -> bool:
    if plain_flag:
        return True
    if os.environ.get("NO_COLOR") is not None:
        return True
    stream = stream if stream is not None else sys.stdout
    return not stream.isatty()


def make_console(*, plain: bool) -> Console:
    """En modo plano se desactiva también el markup de rich (los corchetes
    literales de etiquetas como "[OK]" no deben interpretarse como markup) y
    el ajuste de línea (`soft_wrap`), para que la salida sea estable para
    grep/CI en vez de depender del ancho de la terminal."""
    return Console(
        no_color=plain, highlight=False, emoji=not plain, markup=not plain,
        soft_wrap=plain, force_terminal=False if plain else None,
    )


def render_header(console: Console, *, version: str, plain: bool) -> None:
    if plain:
        console.print(f"LYNCEUS {version}")
        console.print("Validador de seguridad para servidores MCP")
        console.print()
        return

    title = Text()
    title.append("👁️  ", style=AMBER_BRIGHT)
    title.append("L Y N C E U S", style=f"bold {AMBER_BRIGHT}")
    title.append(f"  v{version}", style=GOLD)
    body = Text("Validador de seguridad para servidores MCP", style=GOLD)
    panel = Panel.fit(Text.assemble(title, "\n", body), border_style=AMBER, padding=(1, 4))
    console.print(panel)
    console.print()


def render_sandbox_status(console: Console, *, class_name: str, network: str, plain: bool) -> None:
    label = CLASS_LABELS.get(class_name, class_name)
    isolation = "red interna aislada (sin salida real)" if network != "none" else "sin red"
    if plain:
        console.print(f"[sandbox] {label}: {isolation}")
        return
    text = Text()
    text.append("🛡️  ", style=AMBER_BRIGHT)
    text.append(f"{label}: ", style=f"bold {AMBER_BRIGHT}")
    text.append(isolation, style=GOLD)
    console.print(text)


_T = TypeVar("_T")


def run_with_progress(
    console: Console,
    *,
    class_name: str,
    plain: bool,
    fn: Callable[[], _T],
) -> _T:
    """Ejecuta `fn` (una llamada bloqueante de validación) mostrando progreso por clase.

    `fn` se ejecuta en un hilo aparte porque es una llamada síncrona que
    bloquea en subprocess (docker run): el hilo principal solo necesita
    seguir vivo para refrescar la animación mientras se espera.
    """
    label = CLASS_LABELS.get(class_name, class_name)
    if plain:
        console.print(f"Ejecutando {label}...")
        result = fn()
        console.print(f"{label}: completado")
        return result

    with Progress(
        SpinnerColumn(style=AMBER_BRIGHT),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(style=AMBER, complete_style=AMBER_BRIGHT, pulse_style=GOLD),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task(f"🧪 {label}", total=None)
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(fn)
            while not future.done():
                time.sleep(0.1)
            result = future.result()
        progress.update(task, total=1, completed=1)
    return result


def render_findings_table(console: Console, findings: list[Finding], *, plain: bool) -> None:
    groups = group_findings(findings)
    if not groups:
        return
    if plain:
        console.print("Vulnerabilidades confirmadas:")
        console.print(f"  ({SEVERITY_NOTE})")
        for group in groups:
            class_label = CLASS_LABELS.get(group.vuln_class.value, group.vuln_class.value)
            severity_label = SEVERITY_LABELS.get(group.severity, group.severity)
            console.print(
                f"  - tool={sanitize_untrusted(group.tool)} parametro={sanitize_untrusted(group.parameter)} "
                f"clase={class_label} gravedad={severity_label}"
            )
            for finding in group.findings:
                technique = finding.technique or finding.rule_id
                call = format_reproduction(finding.reproduction)
                console.print(
                    f"      tecnica={sanitize_untrusted(technique)} "
                    f"reproduccion={sanitize_untrusted(call)} "
                    f"evidencia={sanitize_untrusted(finding.evidence)}"
                )
        return

    title = Text("🔍 Vulnerabilidades confirmadas", style=f"bold {AMBER_BRIGHT}")
    table = Table(title=title, caption=SEVERITY_NOTE, border_style=AMBER, header_style=f"bold {GOLD}")
    table.add_column("Gravedad")
    table.add_column("Herramienta")
    table.add_column("Parámetro")
    table.add_column("Clase")
    table.add_column("Técnicas / reproducción / evidencia", overflow="fold")

    for group in groups:
        class_label = CLASS_LABELS.get(group.vuln_class.value, group.vuln_class.value)
        severity_label = SEVERITY_LABELS.get(group.severity, group.severity)
        detail_lines = []
        for finding in group.findings:
            technique = finding.technique or finding.rule_id
            call = format_reproduction(finding.reproduction)
            detail_lines.append(
                f"{sanitize_untrusted(technique)} → {sanitize_untrusted(call)}\n"
                f"  {sanitize_untrusted(finding.evidence)}"
            )
        table.add_row(
            Text(severity_label, style=f"bold {RED}"),
            Text(sanitize_untrusted(group.tool)),
            Text(sanitize_untrusted(group.parameter)),
            Text(class_label),
            Text("\n".join(detail_lines)),
        )
    console.print(table)


def render_inconclusive(console: Console, inconclusive_by_class: dict[str, list[dict]], *, plain: bool) -> None:
    total = sum(len(items) for items in inconclusive_by_class.values())
    if total == 0:
        return
    if plain:
        console.print("Intentos inconclusos:")
        for class_name, items in inconclusive_by_class.items():
            class_label = CLASS_LABELS.get(class_name, class_name)
            for item in items:
                console.print(
                    f"  - clase={class_label} tool={sanitize_untrusted(item.get('tool'))} "
                    f"parametro={sanitize_untrusted(item.get('parameter'))} "
                    f"tecnica={sanitize_untrusted(item.get('technique'))} "
                    f"detalle={sanitize_untrusted(str(item.get('detail') or item.get('status')))}"
                )
        return

    title = Text(f"⚠️  Intentos inconclusos ({total})", style=f"bold {YELLOW}")
    table = Table(title=title, border_style=YELLOW, header_style=f"bold {GOLD}")
    table.add_column("Clase")
    table.add_column("Herramienta")
    table.add_column("Parámetro")
    table.add_column("Técnica")
    table.add_column("Detalle", overflow="fold")
    for class_name, items in inconclusive_by_class.items():
        class_label = CLASS_LABELS.get(class_name, class_name)
        for item in items:
            table.add_row(
                Text(class_label),
                Text(sanitize_untrusted(str(item.get("tool")))),
                Text(sanitize_untrusted(str(item.get("parameter")))),
                Text(sanitize_untrusted(str(item.get("technique")))),
                Text(sanitize_untrusted(str(item.get("detail") or item.get("status")))),
            )
    console.print(table)


@dataclass
class ScanSummary:
    vulnerabilities: int
    techniques: int
    inconclusive: int
    elapsed_seconds: float


def render_summary(console: Console, summary: ScanSummary, *, plain: bool) -> None:
    vuln_text = f"{summary.vulnerabilities} vulnerabilidades confirmadas ({summary.techniques} técnicas)"
    if plain:
        status = "FAIL" if summary.vulnerabilities else ("WARN" if summary.inconclusive else "OK")
        console.print(
            f"[{status}] {vuln_text}, inconclusos={summary.inconclusive} "
            f"tiempo={summary.elapsed_seconds:.1f}s"
        )
        return

    if summary.vulnerabilities:
        icon, style = "❌", RED
    elif summary.inconclusive:
        icon, style = "⚠️ ", YELLOW
    else:
        icon, style = "✅", GREEN

    text = Text()
    text.append(f"{icon} ", style=f"bold {style}")
    text.append(f"{vuln_text}, ", style=f"bold {style}")
    text.append(f"{summary.inconclusive} inconclusos, ", style=style)
    text.append(f"{summary.elapsed_seconds:.1f}s totales", style=style)
    console.print(Panel(text, border_style=style, padding=(0, 2)))


def render_metrics_table(
    console: Console,
    rows: list[tuple[str, ClassMetrics]],
    *,
    plain: bool,
) -> None:
    """`rows` ya incluye la fila "Global" (calculada por el llamador con `core.metrics`)."""
    if plain:
        for label, metrics in rows:
            console.print(
                f"{label}: tp={metrics.tp} fp={metrics.fp} fn={metrics.fn} "
                f"precision={metrics.precision} recall={metrics.recall}"
            )
        return

    title = Text("🧪 Métricas de la validación dinámica", style=f"bold {AMBER_BRIGHT}")
    table = Table(title=title, border_style=AMBER, header_style=f"bold {GOLD}")
    table.add_column("Clase")
    table.add_column("TP", justify="right")
    table.add_column("FP", justify="right")
    table.add_column("FN", justify="right")
    table.add_column("Precisión", justify="right")
    table.add_column("Recall", justify="right")
    for label, metrics in rows:
        style = f"bold {AMBER_BRIGHT}" if label == "Global" else ""
        precision = "—" if metrics.precision is None else f"{metrics.precision:.2f}"
        recall = "—" if metrics.recall is None else f"{metrics.recall:.2f}"
        table.add_row(
            Text(label, style=style),
            Text(str(metrics.tp), style=style),
            Text(str(metrics.fp), style=style),
            Text(str(metrics.fn), style=style),
            Text(precision, style=style),
            Text(recall, style=style),
        )
    console.print(table)


def render_report_paths(console: Console, *, json_path: str | None, report_path: str | None, plain: bool) -> None:
    for label, path in (("JSON", json_path), ("HTML", report_path)):
        if path is None:
            continue
        if plain:
            console.print(f"[{label}] {path}")
        else:
            text = Text()
            text.append("📄 ", style=AMBER_BRIGHT)
            text.append(f"Informe {label}: ", style=f"bold {GOLD}")
            text.append(path, style=GOLD)
            console.print(text)
