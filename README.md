# Lynceus

Validador de seguridad para servidores MCP (Model Context Protocol), en desarrollo. Objetivo: reportar solo los fallos de implementación que consigue reproducir en un entorno aislado.

## Estado (noviembre de 2026)

Hecho:
- Benchmark de 24 casos (inyección de comandos, SSRF y path traversal; versiones vulnerables y corregidas, 18 escritos sin conocer las reglas) en `benchmark/cases/`, con criterios de etiquetado.
- Núcleo con modelo, cargador de etiquetas y métricas (precisión y recall) en `src/lynceus_sec/core/`.
- Reglas taint de Semgrep en `rules/semgrep/` y evaluador reproducible en `scripts/eval_semgrep.py`.
- Sandbox Docker endurecido (sin red o con red interna aislada, solo lectura, sin privilegios, dependencias fijadas con hash) y validación dinámica de las tres clases con canarios en `scripts/eval_dynamic.py`.
- Comparativa con herramientas existentes en `docs/landscape.md`, modelo de amenazas en `docs/threat-model.md` y hoja de ruta en `docs/roadmap.md`.

Resultados actuales (8 casos por clase, 4 vulnerables):

| Clase | Reglas de Semgrep (precisión / recall) | Validación dinámica (precisión / recall) |
|---|---|---|
| Inyección de comandos | 1,00 / 0,25 | 1,00 / 0,75 |
| Path traversal | 0,75 / 0,75 | 1,00 / 1,00 |
| SSRF | 0,67 / 0,50 | 1,00 / 1,00 |
| Global (24 casos) | 0,75 / 0,50 | 1,00 / 0,92 |

El único falso negativo de la validación dinámica es un caso inconcluso por su entorno (`cmdi-03`). Los 24 casos ya se han usado durante el desarrollo: las cifras no son una medida independiente. Ver `docs/landscape.md`.

Pendiente:
- Lote de casos nuevo, no usado para ajustar nada, para una medida independiente.
- Script de reproducción por hallazgo y salida SARIF.
- Todavía no hay nada instalable ni publicado en PyPI.

## Uso responsable

Utilízalo solo contra sistemas propios o con autorización expresa. Los casos del benchmark son vulnerables a propósito: no los expongas a una red ni los ejecutes fuera del sandbox.

## Licencia

Apache-2.0.
