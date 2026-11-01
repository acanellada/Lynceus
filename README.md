# Lynceus

Validador de seguridad para servidores MCP (Model Context Protocol), en desarrollo. Objetivo: reportar solo los fallos de implementación que consigue reproducir en un entorno aislado.

## Estado (octubre de 2026)

Hecho:
- Benchmark de 24 casos (inyección de comandos, SSRF y path traversal; versiones vulnerables y corregidas, 18 escritos sin conocer las reglas) en `benchmark/cases/`, con criterios de etiquetado.
- Núcleo con modelo, cargador de etiquetas y métricas (precisión y recall) en `src/lynceus_sec/core/`.
- Reglas taint de Semgrep en `rules/semgrep/` y evaluador reproducible en `scripts/eval_semgrep.py`.
- Sandbox Docker endurecido (sin red, solo lectura, sin privilegios, dependencias fijadas con hash) y validación dinámica de inyección de comandos y path traversal con canarios en `scripts/eval_dynamic.py`.
- Comparativa con herramientas existentes en `docs/landscape.md`, modelo de amenazas en `docs/threat-model.md` y hoja de ruta en `docs/roadmap.md`.

Resultados actuales (8 casos por clase, 4 vulnerables):

| Clase | Método | TP | FP | FN | Precisión | Recall |
|---|---|---|---|---|---|---|
| Inyección de comandos | Reglas de Semgrep | 1 | 0 | 3 | 1,00 | 0,25 |
| Inyección de comandos | Validación dinámica | 3 | 0 | 1 | 1,00 | 0,75 |
| Path traversal | Reglas de Semgrep | 3 | 1 | 1 | 0,75 | 0,75 |
| Path traversal | Validación dinámica | 4 | 0 | 0 | 1,00 | 1,00 |

El falso negativo de inyección de comandos es un caso inconcluso por su entorno (`cmdi-03`). Las muestras son pequeñas: ver `docs/landscape.md`.

Pendiente:
- Validación dinámica de SSRF (requiere una red interna aislada), script de reproducción por hallazgo y salida SARIF.
- Todavía no hay nada instalable ni publicado en PyPI.

## Uso responsable

Utilízalo solo contra sistemas propios o con autorización expresa. Los casos del benchmark son vulnerables a propósito: no los expongas a una red ni los ejecutes fuera del sandbox.

## Licencia

Apache-2.0.
