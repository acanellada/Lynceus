# Lynceus

Validador de seguridad para servidores MCP (Model Context Protocol), en desarrollo. Objetivo: reportar solo los fallos de implementación que consigue reproducir en un entorno aislado.

## Estado (octubre de 2026)

Hecho:
- Benchmark de 24 casos (inyección de comandos, SSRF y path traversal; versiones vulnerables y corregidas, 18 escritos sin conocer las reglas) en `benchmark/cases/`, con criterios de etiquetado.
- Núcleo con modelo, cargador de etiquetas y métricas (precisión y recall) en `src/lynceus_sec/core/`.
- Reglas taint de Semgrep en `rules/semgrep/` y evaluador reproducible en `scripts/eval_semgrep.py`.
- Sandbox Docker endurecido (sin red, solo lectura, sin privilegios, dependencias fijadas con hash) y validación dinámica de inyección de comandos con canarios en `scripts/eval_dynamic.py`.
- Comparativa con herramientas existentes en `docs/landscape.md`, modelo de amenazas en `docs/threat-model.md` y hoja de ruta en `docs/roadmap.md`.

Resultados actuales en inyección de comandos (8 casos, 4 vulnerables):

| Método | TP | FP | FN | Precisión | Recall |
|---|---|---|---|---|---|
| Reglas de Semgrep | 1 | 0 | 3 | 1,00 | 0,25 |
| Validación dinámica | 3 | 0 | 1 | 1,00 | 0,75 |

El falso negativo de la validación dinámica es un caso inconcluso por su entorno (`cmdi-03`). Las muestras son pequeñas: ver `docs/landscape.md`.

Pendiente:
- Validación dinámica de path traversal y SSRF, script de reproducción por hallazgo y salida SARIF.
- Todavía no hay nada instalable ni publicado en PyPI.

## Uso responsable

Utilízalo solo contra sistemas propios o con autorización expresa. Los casos del benchmark son vulnerables a propósito: no los expongas a una red ni los ejecutes fuera del sandbox.

## Licencia

Apache-2.0.
