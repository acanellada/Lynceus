from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from lynceus_sec.core.model import Label, VulnClass


class _VulnEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vuln_class: VulnClass = Field(alias="class")
    tool: str
    file: str
    parameter: str


class _LabelsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case: str
    vulnerabilities: list[_VulnEntry]
    notes: str | None = None


def load_labels(benchmark_dir: Path) -> dict[str, list[Label]]:
    """Carga labels.yaml de cada subcarpeta de benchmark_dir, indexados por id de caso."""
    labels_by_case: dict[str, list[Label]] = {}

    for case_dir in sorted(p for p in benchmark_dir.iterdir() if p.is_dir()):
        labels_path = case_dir / "labels.yaml"
        if not labels_path.is_file():
            continue

        case_id = case_dir.name
        raw = yaml.safe_load(labels_path.read_text())
        try:
            parsed = _LabelsFile.model_validate(raw)
        except ValidationError as exc:
            raise ValueError(f"labels.yaml inválido en {labels_path}: {exc}") from exc

        if parsed.case != case_id:
            raise ValueError(
                f"El campo 'case' ({parsed.case!r}) de {labels_path} no coincide "
                f"con el nombre de la carpeta ({case_id!r})"
            )

        seen_keys: set[tuple[VulnClass, str]] = set()
        labels: list[Label] = []
        for entry in parsed.vulnerabilities:
            key = (entry.vuln_class, entry.tool)
            if key in seen_keys:
                raise ValueError(
                    f"Etiqueta duplicada en {labels_path}: class={entry.vuln_class.value}, "
                    f"tool={entry.tool!r}"
                )
            seen_keys.add(key)
            labels.append(
                Label(
                    case=case_id,
                    vuln_class=entry.vuln_class,
                    tool=entry.tool,
                    file=entry.file,
                    parameter=entry.parameter,
                )
            )

        labels_by_case[case_id] = labels

    return labels_by_case
