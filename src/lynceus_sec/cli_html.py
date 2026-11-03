"""Informe HTML autónomo de `lynceus scan`: un solo fichero, sin JavaScript ni
recursos externos, con la misma identidad ámbar de la terminal y modo claro/
oscuro según el sistema.

Todo texto que venga del servidor analizado (nombres de tool, parámetros,
mensajes, evidencia) se escapa con `html.escape` antes de insertarse en la
plantilla. Como segunda barrera, el documento lleva una meta
Content-Security-Policy que bloquea cualquier recurso externo y cualquier
script (`default-src 'none'; style-src 'unsafe-inline'`): aunque el escape
fallara, el navegador no ejecutaría ni cargaría nada.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime

from lynceus_sec.cli_env import EnvironmentInfo
from lynceus_sec.core.model import Finding, VulnClass
from lynceus_sec.report import (
    CLASS_LABELS,
    SEVERITY_LABELS,
    SEVERITY_NOTE,
    SSRF_RECEIVER_NOTE,
    FindingGroup,
    count_phrase,
    format_reproduction,
    group_findings,
)

_CSP = "default-src 'none'; style-src 'unsafe-inline'"

_STYLE = """
:root {
  --bg: #fffaf0;
  --bg-panel: #fff3dd;
  --fg: #3a2a0f;
  --fg-muted: #7a5c20;
  --amber: #b9770e;
  --amber-bright: #f0a500;
  --gold: #d4a017;
  --border: #e8c27a;
  --red: #c62828;
  --yellow: #a9790a;
  --green: #2e7d32;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #1b1406;
    --bg-panel: #241a07;
    --fg: #f5e6c8;
    --fg-muted: #d4a017;
    --amber: #f0a500;
    --amber-bright: #ffcc66;
    --gold: #e0b84a;
    --border: #5c4312;
    --red: #ff6b6b;
    --yellow: #f1c40f;
    --green: #6fcf6f;
  }
}
* { box-sizing: border-box; }
body {
  background: var(--bg);
  color: var(--fg);
  font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif;
  margin: 0;
  padding: 2rem;
  line-height: 1.5;
}
.container { max-width: 960px; margin: 0 auto; }
.header {
  border: 2px solid var(--amber);
  border-radius: 12px;
  background: var(--bg-panel);
  padding: 1.5rem 2rem;
  margin-bottom: 1.5rem;
}
.header h1 {
  margin: 0;
  color: var(--amber-bright);
  letter-spacing: 0.15em;
  font-size: 1.6rem;
}
.header .version { color: var(--gold); font-size: 1rem; font-weight: normal; letter-spacing: normal; }
.header p { margin: 0.4rem 0 0; color: var(--gold); }
section { margin-bottom: 2rem; }
h2 { color: var(--amber); border-bottom: 1px solid var(--border); padding-bottom: 0.3rem; }
table { width: 100%; border-collapse: collapse; margin-top: 0.75rem; }
th, td {
  text-align: left;
  padding: 0.5rem 0.6rem;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  word-break: break-word;
}
th { color: var(--gold); font-weight: 600; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9em; }
.badge { padding: 0.15rem 0.5rem; border-radius: 6px; font-weight: 600; font-size: 0.85em; }
.badge-confirmed { background: var(--red); color: #fff; }
.badge-inconclusive { background: var(--yellow); color: #231a00; }
.badge-none { background: var(--green); color: #fff; }
.summary {
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem 1.5rem;
  background: var(--bg-panel);
}
.env dt { color: var(--fg-muted); float: left; width: 14rem; clear: left; }
.env dd { margin: 0 0 0.3rem 14rem; }
.muted { color: var(--fg-muted); font-size: 0.9em; }
.confirmations { list-style: none; margin: 0; padding: 0; }
.confirmations li { margin-bottom: 0.5rem; }
.confirmations li:last-child { margin-bottom: 0; }
"""


def _badge(status: str) -> str:
    label, css = {
        "confirmed": ("confirmado", "badge-confirmed"),
        "inconclusive": ("inconcluso", "badge-inconclusive"),
        "none": ("sin hallazgos", "badge-none"),
    }[status]
    return f'<span class="badge {css}">{html.escape(label)}</span>'


def _confirmations_list(group: FindingGroup) -> str:
    items = []
    for finding in group.findings:
        technique = html.escape(finding.technique or finding.rule_id)
        call = html.escape(format_reproduction(finding.reproduction))
        evidence = html.escape(finding.evidence or "")
        items.append(f"<li><strong>{technique}</strong> &rarr; <span class=\"mono\">{call}</span><br>{evidence}</li>")
    list_html = f'<ul class="confirmations">{"".join(items)}</ul>'
    if group.vuln_class == VulnClass.SSRF:
        list_html += f'<p class="muted">{html.escape(SSRF_RECEIVER_NOTE)}</p>'
    return list_html


def _findings_rows(findings: list[Finding]) -> str:
    groups = group_findings(findings)
    if not groups:
        return '<tr><td colspan="5" class="muted">Sin hallazgos confirmados.</td></tr>'
    rows = []
    for group in groups:
        severity_label = SEVERITY_LABELS.get(group.severity, group.severity)
        class_label = CLASS_LABELS.get(group.vuln_class.value, group.vuln_class.value)
        rows.append(
            "<tr>"
            f"<td>{html.escape(severity_label)}</td>"
            f"<td class=\"mono\">{html.escape(group.tool)}</td>"
            f"<td class=\"mono\">{html.escape(group.parameter or '')}</td>"
            f"<td>{html.escape(class_label)}</td>"
            f"<td>{_confirmations_list(group)}</td>"
            "</tr>"
        )
    return "".join(rows)


def _inconclusive_rows(inconclusive_by_class: dict[str, list[dict]]) -> str:
    all_items = [(class_name, item) for class_name, items in inconclusive_by_class.items() for item in items]
    if not all_items:
        return '<tr><td colspan="5" class="muted">Ningún intento inconcluso.</td></tr>'
    rows = []
    for class_name, item in all_items:
        detail = str(item.get("detail") or item.get("status") or "")
        rows.append(
            "<tr>"
            f"<td>{html.escape(CLASS_LABELS.get(class_name, class_name))}</td>"
            f"<td class=\"mono\">{html.escape(str(item.get('tool', '')))}</td>"
            f"<td class=\"mono\">{html.escape(str(item.get('parameter', '')))}</td>"
            f"<td>{html.escape(str(item.get('technique', '')))}</td>"
            f"<td>{html.escape(detail)}</td>"
            "</tr>"
        )
    return "".join(rows)


def _positive_control_rows(positive_controls_by_class: dict[str, list[dict]]) -> str:
    """Control positivo informativo de path traversal: no cambia la
    clasificación de ninguna vulnerabilidad, solo da contexto."""
    all_items = [(class_name, item) for class_name, items in positive_controls_by_class.items() for item in items]
    if not all_items:
        return '<tr><td colspan="4" class="muted">Sin controles positivos.</td></tr>'
    rows = []
    for class_name, item in all_items:
        rows.append(
            "<tr>"
            f"<td>{html.escape(CLASS_LABELS.get(class_name, class_name))}</td>"
            f"<td class=\"mono\">{html.escape(str(item.get('tool', '')))}</td>"
            f"<td class=\"mono\">{html.escape(str(item.get('parameter', '')))}</td>"
            f"<td>{html.escape(str(item.get('status', '')))}</td>"
            "</tr>"
        )
    return "".join(rows)


def _environment_block(environment: EnvironmentInfo) -> str:
    def row(label: str, value: str | None, *, declared: bool = False) -> str:
        shown = value if value is not None else "desconocido"
        suffix = " (declarada)" if declared and value is not None else ""
        return f"<dt>{html.escape(label)}</dt><dd class=\"mono\">{html.escape(shown)}{html.escape(suffix)}</dd>"

    return (
        "<dl class=\"env\">"
        + row("Versión de Lynceus", environment.lynceus_version)
        + row("Imagen del sandbox", environment.sandbox_image)
        + row("ID de la imagen (docker image inspect)", environment.sandbox_image_id)
        + row("Imagen base (Dockerfile, con digest)", environment.base_image_ref)
        + row("Versión de Python", environment.declared_python_version, declared=True)
        + row("Versión de mcp", environment.declared_mcp_version, declared=True)
        + "</dl>"
    )


def build_html_report(
    *,
    target: str,
    classes: list[str],
    fs_root: str,
    findings: list[Finding],
    inconclusive_by_class: dict[str, list[dict]],
    positive_controls_by_class: dict[str, list[dict]],
    elapsed_seconds: float,
    environment: EnvironmentInfo,
) -> str:
    vulnerabilities_confirmed = len(group_findings(findings))
    techniques_confirmed = len(findings)
    inconclusive_count = sum(len(items) for items in inconclusive_by_class.values())
    status = "confirmed" if vulnerabilities_confirmed else ("inconclusive" if inconclusive_count else "none")
    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    vuln_phrase = count_phrase(vulnerabilities_confirmed, "vulnerabilidad confirmada", "vulnerabilidades confirmadas")
    techniques_phrase = count_phrase(techniques_confirmed, "técnica", "técnicas")
    inconclusive_phrase = count_phrase(inconclusive_count, "intento inconcluso", "intentos inconclusos")

    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{_CSP}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe Lynceus</title>
<style>{_STYLE}</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>👁️ L Y N C E U S <span class="version">v{html.escape(environment.lynceus_version)}</span></h1>
    <p>Validador de seguridad para servidores MCP</p>
  </div>

  <section class="summary">
    <p>{_badge(status)} &nbsp; objetivo: <span class="mono">{html.escape(target)}</span></p>
    <p>Clases analizadas: {html.escape(", ".join(CLASS_LABELS.get(c, c) for c in classes))}</p>
    <p>Límite de sistema de ficheros (path traversal): <span class="mono">{html.escape(fs_root)}</span></p>
    <p>{vuln_phrase} ({techniques_phrase})
       &middot; {inconclusive_phrase}
       &middot; Tiempo total: <strong>{elapsed_seconds:.1f}s</strong></p>
    <p class="muted">Generado el {html.escape(generated_at)}.</p>
  </section>

  <section>
    <h2>🔍 Vulnerabilidades</h2>
    <p class="muted">{html.escape(SEVERITY_NOTE)}</p>
    <table>
      <thead><tr>
        <th>Gravedad</th><th>Herramienta</th><th>Parámetro</th><th>Clase</th>
        <th>Técnicas confirmadas (reproducción y evidencia)</th>
      </tr></thead>
      <tbody>{_findings_rows(findings)}</tbody>
    </table>
  </section>

  <section>
    <h2>⚠️ Intentos inconclusos</h2>
    <table>
      <thead><tr><th>Clase</th><th>Herramienta</th><th>Parámetro</th><th>Técnica</th><th>Detalle</th></tr></thead>
      <tbody>{_inconclusive_rows(inconclusive_by_class)}</tbody>
    </table>
  </section>

  <section>
    <h2>🧭 Controles positivos (informativo)</h2>
    <p class="muted">¿Puede la misma tool/parámetro leer siquiera un fichero normal dentro del
       límite? No cambia la clasificación de ninguna vulnerabilidad.</p>
    <table>
      <thead><tr><th>Clase</th><th>Herramienta</th><th>Parámetro</th><th>Estado</th></tr></thead>
      <tbody>{_positive_control_rows(positive_controls_by_class)}</tbody>
    </table>
  </section>

  <section>
    <h2>🛡️ Entorno</h2>
    {_environment_block(environment)}
  </section>
</div>
</body>
</html>
"""
