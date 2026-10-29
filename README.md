# Lynceus

Validador de seguridad para servidores MCP (Model Context Protocol), en desarrollo temprano. Objetivo: reportar solo los fallos de implementación que consigue reproducir en un entorno aislado.

## Estado (octubre de 2026)

Hecho:
- Benchmark inicial de 6 casos (inyección de comandos, SSRF y path traversal; versión vulnerable y corregida) en `benchmark/cases/`.
- Comparativa de herramientas existentes (Bandit, Semgrep, CodeQL y escáneres de MCP) en `docs/landscape.md`.
- Modelo de amenazas en `docs/threat-model.md`.
- Hoja de ruta en `docs/roadmap.md`.

Pendiente:
- Detector, ejecución en sandbox, canarios, script de reproducción y salida SARIF.
- Todavía no hay nada instalable ni publicado en PyPI.

## Uso responsable

Utilízalo solo contra sistemas propios o con autorización expresa. Los casos del benchmark son vulnerables a propósito: no los expongas a una red.

## Licencia

Apache-2.0.