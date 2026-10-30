"""Valida dinámicamente los casos cmdi-* del benchmark y calcula sus métricas.

Ejecuta cargas de inyección de comandos/argumentos con canarios dentro del
sandbox, confirma los hallazgos con el oráculo de Lynceus (nunca con lo que
reporte el servidor) e informa aparte de los intentos inconclusos.
"""

import sys
from pathlib import Path

from lynceus_sec.core.labels import load_labels
from lynceus_sec.core.metrics import compute_metrics
from lynceus_sec.core.model import VulnClass
from lynceus_sec.validator.cmdi import validate_case
from lynceus_sec.validator.runner import RunnerError

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmark" / "cases"


def main() -> int:
    labels_by_case = load_labels(BENCH)
    cmdi_cases = sorted(p for p in BENCH.iterdir() if p.is_dir() and p.name.startswith("cmdi-"))
    cmdi_labels = {case_id: labels for case_id, labels in labels_by_case.items() if case_id.startswith("cmdi-")}

    all_findings = []
    inconclusive_by_case: dict[str, list[dict]] = {}

    for case_dir in cmdi_cases:
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

    metrics = compute_metrics(all_findings, cmdi_labels)
    cmdi_metrics = metrics.by_class[VulnClass.COMMAND_INJECTION]

    print("\n== métricas (command_injection, solo casos cmdi-*) ==")
    print(
        f"tp={cmdi_metrics.tp} fp={cmdi_metrics.fp} fn={cmdi_metrics.fn} "
        f"precision={cmdi_metrics.precision} recall={cmdi_metrics.recall}"
    )

    labeled_tool_keys = {
        (case_id, label.tool)
        for case_id, labels in cmdi_labels.items()
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
        f"etiquetas de command_injection sin hallazgo por resultados inconclusos: "
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
