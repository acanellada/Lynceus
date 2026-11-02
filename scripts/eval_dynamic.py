"""Envoltorio de línea de comandos sobre `lynceus_sec.validator.bench`.

Mismos argumentos y misma salida que antes de mover la lógica de validación y
métricas a `src/lynceus_sec/validator/bench.py`. Sin --class, mantiene el
comportamiento de siempre (command_injection sobre los casos cmdi-*).
"""

import argparse
import sys

from lynceus_sec.validator.bench import CLASS_CONFIG, CaseResult, run_class_benchmark


def _print_case_start(case_id: str) -> None:
    print(f"== {case_id} ==")


def _print_case_done(result: CaseResult) -> None:
    if result.error is not None:
        print(f"  ERROR ejecutando la validación: {result.error}")
        return
    for finding in result.findings:
        print(f"  CONFIRMED: {finding.tool} ({finding.rule_id}) -> {finding.message}")
    if not result.findings:
        print("  (sin hallazgos confirmados)")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--class", dest="vuln_class_name", choices=sorted(CLASS_CONFIG), default="command_injection")
    args = parser.parse_args()

    prefix = CLASS_CONFIG[args.vuln_class_name]["prefix"]
    result = run_class_benchmark(
        args.vuln_class_name, on_case_start=_print_case_start, on_case_done=_print_case_done,
    )
    class_metrics = result.metrics.by_class[result.vuln_class]

    print(f"\n== métricas ({args.vuln_class_name}, solo casos {prefix}*) ==")
    print(
        f"tp={class_metrics.tp} fp={class_metrics.fp} fn={class_metrics.fn} "
        f"precision={class_metrics.precision} recall={class_metrics.recall}"
    )

    print(
        f"etiquetas de {args.vuln_class_name} sin hallazgo por resultados inconclusos: "
        f"{result.missed_due_to_inconclusive}"
    )

    print("\n== intentos inconclusos por caso ==")
    if not result.inconclusive_by_case:
        print("(ninguno)")
    for case_id, items in result.inconclusive_by_case.items():
        print(f"-- {case_id} --")
        for item in items:
            print(
                f"  tool={item['tool']} parameter={item['parameter']} "
                f"technique={item['technique']} detail={item.get('detail')}"
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
