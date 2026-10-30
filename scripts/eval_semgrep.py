"""Ejecuta las reglas de Semgrep sobre el benchmark y calcula precisión y recall."""

import ast
import json
import subprocess
import sys
from pathlib import Path

from lynceus_sec.core.labels import load_labels
from lynceus_sec.core.metrics import compute_metrics
from lynceus_sec.core.model import Finding, VulnClass

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmark" / "cases"
RULES = ROOT / "rules" / "semgrep" / "mcp-taint.yaml"

RULE_CLASS = {
    "lynceus-mcp-param-to-shell": VulnClass("command_injection"),
    "lynceus-mcp-param-to-path": VulnClass("path_traversal"),
    "lynceus-mcp-param-to-request": VulnClass("ssrf"),
}


def enclosing_function(path: Path, line: int) -> str | None:
    """Nombre de la función más interna que contiene la línea."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = node.end_lineno or node.lineno
            if node.lineno <= line <= end and (best is None or node.lineno > best.lineno):
                best = node
    return best.name if best else None


def run_semgrep() -> dict:
    cmd = ["uvx", "semgrep==1.183.0", "--config", str(RULES), "--metrics=off", "--json", "--quiet", str(BENCH)]
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        sys.exit(f"Semgrep falló ({proc.returncode}):\n{proc.stderr}")
    return json.loads(proc.stdout)


def to_findings(report: dict) -> list[Finding]:
    findings = []
    for r in report.get("results", []):
        rule = next((rid for rid in RULE_CLASS if r["check_id"].endswith(rid)), None)
        if rule is None:
            print(f"aviso: regla desconocida {r['check_id']}", file=sys.stderr)
            continue
        path = Path(r["path"]).resolve()
        case = path.relative_to(BENCH).parts[0]
        tool = enclosing_function(path, r["start"]["line"]) or "?"
        findings.append(
            Finding(
                case=case,
                rule_id=rule,
                vuln_class=RULE_CLASS[rule],
                tool=tool,
                severity=r["extra"].get("severity", "UNKNOWN"),
                message=r["extra"].get("message", ""),
            )
        )
    return findings


def main() -> None:
    labels = load_labels(BENCH)
    findings = to_findings(run_semgrep())
    for f in sorted(findings, key=lambda x: (x.case, x.tool)):
        print(f"hallazgo: {f.case:24} {f.vuln_class.value:18} {f.tool}")
    m = compute_metrics(findings, labels)

    def fmt(v: float | None) -> str:
        return "n/a" if v is None else f"{v:.2f}"

    print(f"\nGLOBAL   TP={m.tp} FP={m.fp} FN={m.fn} precision={fmt(m.precision)} recall={fmt(m.recall)}")
    for vc, cm in m.by_class.items():
        print(f"{vc.value:18} TP={cm.tp} FP={cm.fp} FN={cm.fn} precision={fmt(cm.precision)} recall={fmt(cm.recall)}")


if __name__ == "__main__":
    main()