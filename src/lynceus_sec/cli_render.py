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
from lynceus_sec.core.model import Finding, VulnClass
from lynceus_sec.report import (
    CAPABILITY_EXPLANATION,
    CLASS_LABELS,
    SEVERITY_LABELS,
    SEVERITY_NOTE,
    SSRF_RECEIVER_NOTE,
    FindingGroup,
    count_phrase,
    format_calls,
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


def render_fs_root(console: Console, fs_root: str, *, plain: bool) -> None:
    """Línea informativa (solo cuando se valida path traversal) con el
    límite de sistema de ficheros usado: el `HOME` del servidor analizado y
    la referencia frente a la que se decide qué queda "fuera" en los
    canarios de lectura."""
    if plain:
        console.print(f"[fs-root] limite de sistema de ficheros: {fs_root}")
        return
    text = Text()
    text.append("📁 ", style=AMBER_BRIGHT)
    text.append("Límite de sistema de ficheros: ", style=f"bold {GOLD}")
    text.append(fs_root, style=GOLD)
    console.print(text)


def render_target_image(console: Console, *, image: str, image_id: str | None, plain: bool) -> None:
    """Imagen en la que corrió el servidor analizado (ver `cli_env.collect_environment_info`)."""
    id_display = image_id or "desconocido"
    if plain:
        console.print(f"[imagen-objetivo] {image} (id: {id_display})")
        return
    text = Text()
    text.append("🎯 ", style=AMBER_BRIGHT)
    text.append("Imagen objetivo: ", style=f"bold {GOLD}")
    text.append(image, style=GOLD)
    text.append(f" (id: {id_display})", style=GOLD)
    console.print(text)


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


def _findings_summary_table(groups: list[FindingGroup]) -> Table:
    """Una fila por vulnerabilidad: gravedad, herramienta, parámetro, clase y
    número de técnicas. Sin columna de reproducción/evidencia (eso va en el
    bloque a todo el ancho de abajo), así ninguna columna es tan estrecha
    como para partir una URL larga."""
    title = Text(
        f"🔍 {count_phrase(len(groups), 'vulnerabilidad confirmada', 'vulnerabilidades confirmadas')}",
        style=f"bold {AMBER_BRIGHT}",
    )
    table = Table(title=title, caption=SEVERITY_NOTE, border_style=AMBER, header_style=f"bold {GOLD}")
    table.add_column("Gravedad")
    table.add_column("Herramienta")
    table.add_column("Parámetro")
    table.add_column("Clase")
    table.add_column("Técnicas", justify="right")
    for group in groups:
        class_label = CLASS_LABELS.get(group.vuln_class.value, group.vuln_class.value)
        severity_label = SEVERITY_LABELS.get(group.severity, group.severity)
        table.add_row(
            Text(severity_label, style=f"bold {RED}"),
            Text(sanitize_untrusted(group.tool)),
            Text(sanitize_untrusted(group.parameter)),
            Text(class_label),
            Text(str(len(group.findings))),
        )
    return table


def _finding_detail_panel(index: int, group: FindingGroup) -> Panel:
    """Bloque a todo el ancho de una vulnerabilidad: cada técnica con su
    reproducción (una llamada por línea) y su evidencia."""
    class_label = CLASS_LABELS.get(group.vuln_class.value, group.vuln_class.value)
    severity_label = SEVERITY_LABELS.get(group.severity, group.severity)

    header = Text()
    header.append(f"Vulnerabilidad {index}", style=f"bold {AMBER_BRIGHT}")
    header.append(f" · {severity_label}", style=f"bold {RED}")
    header.append(" · ")
    header.append(sanitize_untrusted(group.tool), style="bold")
    if group.parameter:
        header.append(f" (parámetro {sanitize_untrusted(group.parameter)})")
    header.append(f" · {class_label}", style=GOLD)

    body = Text()
    for finding in group.findings:
        technique = finding.technique or finding.rule_id
        body.append(f"• {sanitize_untrusted(technique)}\n", style=f"bold {GOLD}")
        for line in format_calls(finding.reproduction):
            body.append(f"    {sanitize_untrusted(line)}\n")
        body.append(f"    {sanitize_untrusted(finding.evidence)}\n")
    if group.vuln_class == VulnClass.SSRF:
        body.append(f"\n{SSRF_RECEIVER_NOTE}", style="italic")

    return Panel(Text.assemble(header, "\n\n", body), border_style=AMBER, padding=(1, 2))


def _render_findings_plain(console: Console, groups: list[FindingGroup]) -> None:
    console.print(f"{count_phrase(len(groups), 'vulnerabilidad confirmada', 'vulnerabilidades confirmadas')}:")
    console.print(f"  ({SEVERITY_NOTE})")
    for index, group in enumerate(groups, start=1):
        class_label = CLASS_LABELS.get(group.vuln_class.value, group.vuln_class.value)
        severity_label = SEVERITY_LABELS.get(group.severity, group.severity)
        console.print(
            f"  {index}. gravedad={severity_label} tool={sanitize_untrusted(group.tool)} "
            f"parametro={sanitize_untrusted(group.parameter)} clase={class_label} "
            f"tecnicas={len(group.findings)}"
        )

    console.print()
    console.print("Detalle:")
    for index, group in enumerate(groups, start=1):
        class_label = CLASS_LABELS.get(group.vuln_class.value, group.vuln_class.value)
        severity_label = SEVERITY_LABELS.get(group.severity, group.severity)
        console.print(
            f"  [{index}] tool={sanitize_untrusted(group.tool)} parametro={sanitize_untrusted(group.parameter)} "
            f"clase={class_label} gravedad={severity_label}"
        )
        for finding in group.findings:
            technique = finding.technique or finding.rule_id
            console.print(f"      tecnica={sanitize_untrusted(technique)}")
            for line in format_calls(finding.reproduction):
                console.print(f"        {sanitize_untrusted(line)}")
            console.print(f"        evidencia={sanitize_untrusted(finding.evidence)}")
        if group.vuln_class == VulnClass.SSRF:
            console.print(f"      nota={SSRF_RECEIVER_NOTE}")


def render_findings_table(console: Console, findings: list[Finding], *, plain: bool) -> None:
    groups = group_findings(findings)
    if not groups:
        return

    if plain:
        _render_findings_plain(console, groups)
        return

    console.print(_findings_summary_table(groups))
    console.print()
    for index, group in enumerate(groups, start=1):
        console.print(_finding_detail_panel(index, group))


def render_inconclusive(console: Console, inconclusive_by_class: dict[str, list[dict]], *, plain: bool) -> None:
    total = sum(len(items) for items in inconclusive_by_class.values())
    if total == 0:
        return
    if plain:
        console.print(f"{count_phrase(total, 'intento inconcluso', 'intentos inconclusos')}:")
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

    title = Text(
        f"⚠️  {count_phrase(total, 'intento inconcluso', 'intentos inconclusos')}", style=f"bold {YELLOW}"
    )
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


def render_positive_controls(console: Console, positive_controls_by_class: dict[str, list[dict]], *, plain: bool) -> None:
    """Control positivo informativo de path traversal: ¿puede la misma
    tool/parámetro leer siquiera un fichero normal dentro del límite? No
    cambia la clasificación de ninguna vulnerabilidad ni el resumen final."""
    total = sum(len(items) for items in positive_controls_by_class.values())
    if total == 0:
        return
    if plain:
        console.print(f"{count_phrase(total, 'control positivo', 'controles positivos')} (informativo):")
        for class_name, items in positive_controls_by_class.items():
            class_label = CLASS_LABELS.get(class_name, class_name)
            for item in items:
                console.print(
                    f"  - clase={class_label} tool={sanitize_untrusted(item.get('tool'))} "
                    f"parametro={sanitize_untrusted(item.get('parameter'))} "
                    f"estado={sanitize_untrusted(item.get('status'))}"
                )
        return

    title = Text(
        f"🧭 {count_phrase(total, 'control positivo', 'controles positivos')} (informativo)",
        style=f"bold {GOLD}",
    )
    table = Table(title=title, border_style=GOLD, header_style=f"bold {GOLD}")
    table.add_column("Clase")
    table.add_column("Herramienta")
    table.add_column("Parámetro")
    table.add_column("Estado")
    for class_name, items in positive_controls_by_class.items():
        class_label = CLASS_LABELS.get(class_name, class_name)
        for item in items:
            table.add_row(
                Text(class_label),
                Text(sanitize_untrusted(str(item.get("tool")))),
                Text(sanitize_untrusted(str(item.get("parameter")))),
                Text(sanitize_untrusted(str(item.get("status")))),
            )
    console.print(table)


def _capability_detail_panel(index: int, class_name: str, item: dict) -> Panel:
    """Bloque a todo el ancho de una capacidad: la sonda que la detectó y
    cada técnica de inyección agrupada bajo ella, con reproducción."""
    class_label = CLASS_LABELS.get(class_name, class_name)

    header = Text()
    header.append(f"Capacidad {index}", style=f"bold {GOLD}")
    header.append(" · ")
    header.append(sanitize_untrusted(item.get("tool")), style="bold")
    if item.get("parameter"):
        header.append(f" (parámetro {sanitize_untrusted(item['parameter'])})")
    header.append(f" · {class_label}", style=GOLD)

    body = Text()
    probe = item.get("probe")
    if probe:
        body.append("• sonda: ", style=f"bold {GOLD}")
        body.append(f"{sanitize_untrusted(probe.get('payload'))}\n")
        for line in format_calls(probe.get("reproduction")):
            body.append(f"    {sanitize_untrusted(line)}\n")
        body.append(f"    {sanitize_untrusted(probe.get('evidence'))}\n")
    for confirmation in item.get("confirmations", []):
        body.append(f"• {sanitize_untrusted(confirmation.get('technique'))}\n", style=f"bold {GOLD}")
        for line in format_calls(confirmation.get("reproduction")):
            body.append(f"    {sanitize_untrusted(line)}\n")
        body.append(f"    {sanitize_untrusted(confirmation.get('evidence'))}\n")
    body.append(f"\n{CAPABILITY_EXPLANATION}", style="italic")

    return Panel(Text.assemble(header, "\n\n", body), border_style=GOLD, padding=(1, 2))


def render_capabilities(console: Console, capabilities_by_class: dict[str, list[dict]], *, plain: bool) -> None:
    """Capacidades de ejecución de comandos por diseño (ver sonda en cmdi.py):
    no son vulnerabilidades, no cambian el código de salida; se muestran
    aparte, con su reproducción y la explicación de por qué importan."""
    total = sum(len(items) for items in capabilities_by_class.values())
    if total == 0:
        return

    if plain:
        console.print(f"{count_phrase(total, 'capacidad detectada', 'capacidades detectadas')}:")
        console.print(f"  ({CAPABILITY_EXPLANATION})")
        for class_name, items in capabilities_by_class.items():
            class_label = CLASS_LABELS.get(class_name, class_name)
            for item in items:
                console.print(
                    f"  - clase={class_label} tool={sanitize_untrusted(item.get('tool'))} "
                    f"parametro={sanitize_untrusted(item.get('parameter'))}"
                )
                probe = item.get("probe")
                if probe:
                    for line in format_calls(probe.get("reproduction")):
                        console.print(f"      sonda: {sanitize_untrusted(line)}")
                for confirmation in item.get("confirmations", []):
                    console.print(f"      tecnica={sanitize_untrusted(confirmation.get('technique'))}")
                    for line in format_calls(confirmation.get("reproduction")):
                        console.print(f"        {sanitize_untrusted(line)}")
        return

    title = Text(f"🧰 {count_phrase(total, 'capacidad detectada', 'capacidades detectadas')}", style=f"bold {GOLD}")
    table = Table(title=title, caption=CAPABILITY_EXPLANATION, border_style=GOLD, header_style=f"bold {GOLD}")
    table.add_column("Clase")
    table.add_column("Herramienta")
    table.add_column("Parámetro")
    table.add_column("Confirmaciones", justify="right")

    panels: list[Panel] = []
    index = 0
    for class_name, items in capabilities_by_class.items():
        class_label = CLASS_LABELS.get(class_name, class_name)
        for item in items:
            index += 1
            table.add_row(
                Text(class_label),
                Text(sanitize_untrusted(item.get("tool"))),
                Text(sanitize_untrusted(item.get("parameter"))),
                Text(str(len(item.get("confirmations", [])))),
            )
            panels.append(_capability_detail_panel(index, class_name, item))

    console.print(table)
    console.print()
    for panel in panels:
        console.print(panel)


@dataclass
class ScanSummary:
    vulnerabilities: int
    techniques: int
    inconclusive: int
    elapsed_seconds: float


def render_summary(console: Console, summary: ScanSummary, *, plain: bool) -> None:
    vuln_phrase = count_phrase(summary.vulnerabilities, "vulnerabilidad confirmada", "vulnerabilidades confirmadas")
    techniques_phrase = count_phrase(summary.techniques, "técnica", "técnicas")
    inconclusive_phrase = count_phrase(summary.inconclusive, "inconcluso", "inconclusos")
    vuln_text = f"{vuln_phrase} ({techniques_phrase})"

    if plain:
        status = "FAIL" if summary.vulnerabilities else ("WARN" if summary.inconclusive else "OK")
        console.print(f"[{status}] {vuln_text}, {inconclusive_phrase} tiempo={summary.elapsed_seconds:.1f}s")
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
    text.append(f"{inconclusive_phrase}, ", style=style)
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


def render_build_result(console: Console, result, *, plain: bool) -> None:
    """Resultado de `lynceus build`: etiqueta de la imagen, fichero resuelto
    y versión fijada de cada paquete. `result` viene de `validator.build`."""
    if plain:
        console.print(f"[tag] {result.tag}")
        console.print(f"[resuelto] {result.resolved_path}")
        if result.skipped_image_build:
            console.print("[build] la imagen ya existía, no se reconstruye")
        for name, ver in result.versions:
            console.print(f"  {sanitize_untrusted(name)}=={sanitize_untrusted(ver)}")
        return

    title = Text(f"📦 Imagen objetivo: {result.tag}", style=f"bold {AMBER_BRIGHT}")
    table = Table(title=title, border_style=AMBER, header_style=f"bold {GOLD}")
    table.add_column("Paquete")
    table.add_column("Versión")
    for name, ver in result.versions:
        table.add_row(Text(sanitize_untrusted(name)), Text(sanitize_untrusted(ver)))
    console.print(table)
    console.print()

    note = Text()
    note.append("📄 ", style=AMBER_BRIGHT)
    note.append("Fichero resuelto: ", style=f"bold {GOLD}")
    note.append(str(result.resolved_path), style=GOLD)
    console.print(note)

    if result.skipped_image_build:
        console.print(Text("La imagen ya existía; no se reconstruye.", style=GOLD))


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
