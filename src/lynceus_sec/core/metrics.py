from __future__ import annotations

from pydantic import BaseModel

from lynceus_sec.core.model import Finding, Label, VulnClass


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


class ClassMetrics(BaseModel):
    tp: int
    fp: int
    fn: int
    precision: float | None
    recall: float | None


class Metrics(BaseModel):
    tp: int
    fp: int
    fn: int
    precision: float | None
    recall: float | None
    by_class: dict[VulnClass, ClassMetrics]


def compute_metrics(findings: list[Finding], labels: dict[str, list[Label]]) -> Metrics:
    """Compara hallazgos contra etiquetas por (case, vuln_class, tool).

    Deduplica hallazgos repetidos con la misma clave antes de contar. Lanza
    ValueError si un hallazgo referencia un caso ausente de `labels`.
    """
    known_cases = set(labels)

    finding_keys: set[tuple[str, VulnClass, str]] = set()
    for finding in findings:
        if finding.case not in known_cases:
            raise ValueError(
                f"El hallazgo referencia el caso {finding.case!r}, "
                "que no existe en las etiquetas"
            )
        finding_keys.add((finding.case, finding.vuln_class, finding.tool))

    label_keys: set[tuple[str, VulnClass, str]] = {
        (label.case, label.vuln_class, label.tool)
        for case_labels in labels.values()
        for label in case_labels
    }

    tp_keys = finding_keys & label_keys
    fp_keys = finding_keys - label_keys
    fn_keys = label_keys - finding_keys

    tp_by_class = dict.fromkeys(VulnClass, 0)
    fp_by_class = dict.fromkeys(VulnClass, 0)
    fn_by_class = dict.fromkeys(VulnClass, 0)

    for _, vuln_class, _tool in tp_keys:
        tp_by_class[vuln_class] += 1
    for _, vuln_class, _tool in fp_keys:
        fp_by_class[vuln_class] += 1
    for _, vuln_class, _tool in fn_keys:
        fn_by_class[vuln_class] += 1

    tp, fp, fn = len(tp_keys), len(fp_keys), len(fn_keys)

    by_class = {
        vuln_class: ClassMetrics(
            tp=tp_by_class[vuln_class],
            fp=fp_by_class[vuln_class],
            fn=fn_by_class[vuln_class],
            precision=_ratio(tp_by_class[vuln_class], tp_by_class[vuln_class] + fp_by_class[vuln_class]),
            recall=_ratio(tp_by_class[vuln_class], tp_by_class[vuln_class] + fn_by_class[vuln_class]),
        )
        for vuln_class in VulnClass
    }

    return Metrics(
        tp=tp,
        fp=fp,
        fn=fn,
        precision=_ratio(tp, tp + fp),
        recall=_ratio(tp, tp + fn),
        by_class=by_class,
    )
