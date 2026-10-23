# Panorama de competidores

Fecha de la revisión: 

| Proyecto | Enfoque (estático/dinámico/runtime) | Qué detecta | Valida con evidencia reproducible (sí/no) | Licencia | Actividad reciente | Qué NO hace |
|---|---|---|---|---|---|---|

| Cisco mcp-scanner | Estático + heurístico: YARA, LLM como juez, API de Cisco, meta-analizador de falsos positivos; análisis de comportamiento de código (10 lenguajes); sandbox Docker solo para analizar paquetes PyPI/npm | Tool poisoning, prompt injection en descripciones, desajuste descripción/código, CVE en dependencias, malware en binarios | No según el README (no invoca herramientas ni ejecuta el código analizado) | Apache-2.0 | Activa; protocolo 2026-07-28 | SARIF (no existe en sus formatos); evidencia reproducible por hallazgo (no descrita); métricas públicas (sin verificar) |

| Snyk Agent Scan (antes mcp-scan, Invariant Labs) | Estático sobre metadatos, análisis en la API de Snyk; descubrimiento de agentes y skills en la máquina; modo flota (Evo) | Prompt injection, contenido no confiable, datos privados, capacidades destructivas (v0.6); tool poisoning/shadowing/toxic flows (v0.5) | No según el README (no invoca herramientas) | Por verificar en el repo | Activo; v0.5 en retirada; salida experimental | Código fuente del servidor; fallos de implementación; evidencia reproducible; funcionamiento sin API ni cuenta; SARIF |


## Hallazgos

Cisco mcp-scanner:
- Test local (21/10/2026): YARA sobre `cmdi-01-vulnerable` y `cmdi-01-fixed` -> Safe en ambos (esperable: solo analiza metadatos).
- Analizador de comportamiento: NO PROBADO (requiere clave LLM). Pendiente de ejecutar sobre el benchmark completo.
- Observado: el escáner lanza el servidor objetivo para listar herramientas; mcpval deberá ejecutar siempre en sandbox.
- Observado: dos generaciones de protocolo (`server/discover` moderno e `initialize()` legacy); el adaptador de mcpval debe soportar ambas.




## Diferenciación

mcpval se diferencia en: