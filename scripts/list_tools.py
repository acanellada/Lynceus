"""Lista las herramientas de cada caso del benchmark dentro del sandbox.

Comprueba que cada herramienta etiquetada en labels.yaml existe realmente en el
servidor (error si falta). Las herramientas sin etiqueta se listan solo como
información: los casos corregidos no tienen etiquetas y algunos servidores
exponen varias herramientas.
"""

import sys
from pathlib import Path

from lynceus_sec.core.labels import load_labels
from lynceus_sec.validator.runner import RunnerError, run_harness

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmark" / "cases"


def main() -> int:
    labels_by_case = load_labels(BENCH)
    had_errors = False

    for case_dir in sorted(p for p in BENCH.iterdir() if p.is_dir()):
        case_id = case_dir.name
        print(f"== {case_id} ==")

        try:
            tools = run_harness(case_dir)
        except RunnerError as exc:
            print(f"  ERROR ejecutando el harness: {exc}")
            had_errors = True
            continue

        tool_names = {tool["name"] for tool in tools}
        labeled_names = {label.tool for label in labels_by_case.get(case_id, [])}

        missing = labeled_names - tool_names
        unlabeled = tool_names - labeled_names

        for name in sorted(tool_names):
            print(f"  tool: {name}")
        for name in sorted(missing):
            print(f"  ERROR: etiquetada en labels.yaml pero ausente en el servidor: {name}")
            had_errors = True
        for name in sorted(unlabeled):
            print(f"  info: herramienta sin etiqueta: {name}")

    return 1 if had_errors else 0


if __name__ == "__main__":
    sys.exit(main())
