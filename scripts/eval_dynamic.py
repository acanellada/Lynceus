"""Valida dinámicamente los casos de una clase de vulnerabilidad y calcula sus métricas.

Ejecuta cargas con canarios dentro del sandbox, confirma los hallazgos con el
oráculo de Lynceus (nunca con lo que reporte el servidor) e informa aparte de
los intentos inconclusos. Sin --class, mantiene el comportamiento de siempre
(command_injection sobre los casos cmdi-*).
"""

import argparse
import sys
from pathlib import Path

from lynceus_sec.core.labels import load_labels
from lynceus_sec.core.metrics import compute_metrics
from lynceus_sec.core.model import VulnClass
from lynceus_sec.validator.runner import RunnerError

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmark" / "cases"

_CLASS_CONFIG = {
    "command_injection": {"prefix": "cmdi-", "vuln_class": VulnClass.COMMAND_INJECTION},
    "path_traversal": {"prefix": "ptrav-", "vuln_class": VulnClass.PATH_TRAVERSAL},
    "ssrf": {"prefix": "ssrf-", "vuln_class": VulnClass.SSRF},
}


def _validate_case_for(vuln_class: VulnClass):
    if vuln_class is VulnClass.COMMAND_INJECTION:
        from lynceus_sec.validator.cmdi import validate_case
    elif vuln_class is VulnClass.PATH_TRAVERSAL:
        from lynceus_sec.validator.ptrav import validate_case
    else:
        from lynceus_sec.validator.ssrf import validate_case
    return validate_case


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--class", dest="vuln_class_name", choices=sorted(_CLASS_CONFIG), default="command_injection")
    args = parser.parse_args()

    config = _CLASS_CONFIG[args.vuln_class_name]
    prefix = config["prefix"]
    vuln_class = config["vuln_class"]
    validate_case = _validate_case_for(vuln_class)

    labels_by_case = load_labels(BENCH)
    cases = sorted(p for p in BENCH.iterdir() if p.is_dir() and p.name.startswith(prefix))
    class_labels = {case_id: labels for case_id, labels in labels_by_case.items() if case_id.startswith(prefix)}

    all_findings = []
    inconclusive_by_case: dict[str, list[dict]] = {}

    for case_dir in cases:
        case_id = case_dir.name
        print(f"== {case_id} ==")
        try:
            findings, inconclusive = validate_case(case_dir)
        except RunnerError as exc:
            print(f"  ERROR ejecutando la validación: {exc}")
            continue

        for finding in findings:
            print(f"  CONFIRMED: {finding.tool} ({finding.rule_id}) -> {finding.message}")
        if not findings:
            print("  (sin hallazgos confirmados)")
        if inconclusive:
            inconclusive_by_case[case_id] = inconclusive

        all_findings.extend(findings)

    metrics = compute_metrics(all_findings, class_labels)
    class_metrics = metrics.by_class[vuln_class]

    print(f"\n== métricas ({args.vuln_class_name}, solo casos {prefix}*) ==")
    print(
        f"tp={class_metrics.tp} fp={class_metrics.fp} fn={class_metrics.fn} "
        f"precision={class_metrics.precision} recall={class_metrics.recall}"
    )

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
    print(
        f"etiquetas de {args.vuln_class_name} sin hallazgo por resultados inconclusos: "
        f"{len(missed_due_to_inconclusive)}"
    )

    print("\n== intentos inconclusos por caso ==")
    if not inconclusive_by_case:
        print("(ninguno)")
    for case_id, items in inconclusive_by_case.items():
        print(f"-- {case_id} --")
        for item in items:
            print(
                f"  tool={item['tool']} parameter={item['parameter']} "
                f"technique={item['technique']} detail={item.get('detail')}"
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
