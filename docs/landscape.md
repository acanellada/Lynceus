# Panorama de competidores

Fecha de la revisión: 21-25/10/2026. Fuentes: READMEs públicos, lectura parcial de código y pruebas locales del autor. Lo anotado solo desde un README no está verificado en ejecución.

| Proyecto | Enfoque (estático/dinámico/runtime) | Qué detecta | Valida con evidencia reproducible (sí/no) | Licencia | Actividad reciente | Qué NO hace |
|---|---|---|---|---|---|---|
| Cisco mcp-scanner | Estático + heurístico: YARA, LLM como juez, API de Cisco, meta-analizador de falsos positivos; análisis de comportamiento de código (10 lenguajes); sandbox Docker solo para analizar paquetes PyPI/npm | Tool poisoning, prompt injection en descripciones, desajuste descripción/código, CVE en dependencias, malware en binarios | No según el README (no invoca herramientas ni ejecuta el código analizado) | Apache-2.0 | Activa; soporta protocolo 2026-07-28 | SARIF (no existe en sus formatos); evidencia reproducible por hallazgo (no descrita); métricas públicas (sin verificar) |
| Snyk Agent Scan (antes mcp-scan, Invariant Labs) | Estático sobre metadatos, análisis en la API de Snyk; descubrimiento de agentes y skills en la máquina; modo flota (Evo) | Prompt injection, contenido no confiable, datos privados, capacidades destructivas (v0.6); tool poisoning/shadowing/toxic flows (v0.5) | No según el README (no invoca herramientas) | Por verificar en el repo | Activo; v0.5 en retirada; salida experimental | Código fuente del servidor; fallos de implementación; evidencia reproducible; funcionamiento sin API ni cuenta; SARIF |
| MCPSafetyScanner (Radosevich y Halloran, académico, arXiv 2504.03767) | Dinámico con agentes LLM (framework agno): un equipo de agentes con acceso a las herramientas del servidor lo audita y redacta un informe; otro agente investiga en la web para citar fuentes. Admite OpenAI, Azure y Ollama | Escenarios de abuso de las herramientas (volcado de credenciales, claves SSH, puertas traseras en scripts de arranque), con ejemplos de comandos y remediaciones | No: sin paso de verificación en el código (ninguna coincidencia de verif/confirm/evidence/proof/reproduc) | MPL-2.0 | Abandonado: último push 10/04/2025; 179 estrellas, 2 issues | Fallos de implementación por parámetro; verificar el hallazgo con una reproducción; sandbox propio (no visto); salida estructurada (SARIF/JSON) y CI |
| MCP-Shield (riseandignite; solo README) | Estático sobre metadatos: lee configs de clientes MCP, lista las herramientas de cada servidor y busca patrones en descripciones y esquemas; análisis opcional con Claude (clave propia); `--identify-as` para detectar servidores que cambian según el cliente | Tool poisoning, instrucciones ocultas, acceso a ficheros sensibles (.env, ~/.ssh), shadowing, posibles canales de exfiltración, escalada entre servidores | No: avisos por coincidencia de patrones, con análisis de IA opcional | MIT | Parado: 555 estrellas, último push 26/04/2025; 8 issues y PRs abiertos; un tercero se ofrece a mantenerlo | Código fuente del servidor; fallos de implementación; confirmar con ejecución; salida JSON (PR #10 sin fusionar) |
| mcp-context-protector (Trail of Bits; solo README) | Ejecución: envoltorio entre cliente y servidor MCP; fija la configuración en el primer uso, bloquea cambios no aprobados, analiza respuestas con LlamaFirewall y las pone en cuarentena, sanea caracteres ANSI | Cambios de configuración (rug pulls), line jumping, inyección de prompt en respuestas, engaño con caracteres de control | No aplica: es control en ejecución, no auditoría | Apache-2.0 | Mantenido: último push 14/04/2026; 18 issues y PRs abiertos | Auditar el código del servidor; encontrar fallos de implementación; validar antes del despliegue |

## Descartados o adyacentes (no son competidores directos)

- sammcj/mcp-snyk: servidor MCP que expone Snyk a un agente. Usa un escáner, no audita servidores MCP.
- saurabh-yergattikar/ShieldMCP: proxy de seguridad en ejecución, creado en julio de 2026 y con 6 estrellas. Adyacente a mcp-context-protector, no revisado.

## Pendientes de revisar

- Papers y benchmarks académicos de seguridad de MCP (taxonomías y posibles benchmarks públicos de escáneres).
- Servidores MCP vulnerables a propósito (corpus para el benchmark; comprobar licencia).
- promptfoo (¿tiene pruebas específicas de MCP?).
- CodeQL sobre los 6 casos del benchmark.
- Modo behavioral de Cisco (requiere clave LLM).

## Línea base SAST genérico (22-23/10/2026, n=1 por clase, casos del autor)

| Caso | Bandit 1.9.4 | Semgrep security-audit + owasp-top-ten |
|---|---|---|
| cmdi-01-vulnerable | B602 High | detectado |
| cmdi-01-fixed | 3 Low (ruido) | limpio |
| ptrav-01-vulnerable | sin hallazgo | sin hallazgo |
| ptrav-01-fixed | sin hallazgo | sin hallazgo |
| ssrf-01-vulnerable | B310 Medium | dynamic-urllib-use-detected |
| ssrf-01-fixed | B310 Medium | dynamic-urllib-use-detected |

Lectura:
- Inyección de comandos: resuelta por SAST genérico (Semgrep distingue el caso corregido).
- SSRF: las reglas son de patrón y no distinguen validación de host (marcan vulnerable y corregido por igual).
- Path traversal: sin cobertura en ninguna configuración probada.

Limitaciones: n=1 por clase, casos del autor, sin CodeQL (probablemente cubre path injection y SSRF con flujo de datos; sin verificar). Modo behavioral de Cisco sin probar (requiere clave LLM).

## Hallazgos

### Cisco mcp-scanner

- Test local (21/10/2026): YARA sobre `cmdi-01-vulnerable` y `cmdi-01-fixed` -> Safe en ambos (esperable: solo analiza metadatos).
- Analizador de comportamiento: NO PROBADO (requiere clave LLM). Pendiente de ejecutar sobre el benchmark completo.
- Observado: el escáner lanza el servidor objetivo para listar herramientas; Lynceus deberá ejecutar siempre en sandbox.
- Observado: dos generaciones de protocolo (`server/discover` moderno e `initialize()` legacy); el adaptador de Lynceus debe soportar ambas.

### Snyk Agent Scan

- La salida de la CLI es explícitamente experimental y puede cambiar sin aviso: mala base para un benchmark comparativo reproducible.
- El análisis se hace en la API de Snyk (requiere token y envía nombres, descripciones y contenido de skills con secretos ocultados).
- Su README considera abuso el uso de la API estándar para escaneos a gran escala. Revisar términos antes de usarla como línea base.
- No probado localmente.

### MCPSafetyScanner

- Genera informes con ejemplos de explotación redactados por un LLM; el código no contiene paso de verificación ni salida estructurada. Prototipo abandonado desde abril de 2025.
- Su prompt instruye a los agentes a intentar acciones ofensivas contra el entorno configurado: no ejecutar fuera de un entorno desechable.
- La idea "agentes de IA que auditan servidores MCP" ya está publicada: no es diferenciación por sí sola.

### MCP-Shield

- 555 estrellas, creado el 15/04/2025 y con el último push el 26/04/2025. Issue #14: un tercero se ofrece a mantenerlo. PRs sin fusionar: export JSON (#10), soporte Bedrock (#9), cambios con ruptura (#11).
- Falso positivo reportado públicamente (issue #8 y awslabs/mcp#159): "Sensitive file access: .env", HIGH, sobre un servidor de AWS Labs. Un solo caso, valoración del reportante, sin verificar.

### mcp-context-protector

- Es complementario, no competidor: control en ejecución frente a validación previa.
- Issue #59 (fail-open ante nombres de herramienta no registrados) con PR #60 sin fusionar: ejemplo de fallo de lógica que ninguna regla de patrón detecta y que una llamada dinámica confirmaría. Afirmación de un tercero, sin verificar.

### Qué está cubierto y qué no

- Bien cubierto: metadatos, prompt injection y tool poisoning (Cisco, Snyk, MCP-Shield, según sus READMEs); cadena de suministro (Cisco); control en ejecución (mcp-context-protector); inyección de comandos (SAST genérico).
- Mal cubierto: SSRF (reglas de patrón que no distinguen una validación real).
- No encontrado en lo revisado: path traversal en servidores MCP; autorización con fallo abierto; y verificación de cada hallazgo con una reproducción. Esto último, ninguno de los cinco proyectos lo describe ni lo muestra en el código leído, pero la revisión es parcial.

## Direcciones evaluadas

| Dirección | Cubierta por alguien (sí/no/no sé) | Medible con un caso (sí/no) | Veredicto |
|---|---|---|---|
| Autorización con fallo abierto (patrón del issue #59) | No sé; ningún SAST de patrón parece verla | Sí: caso `authz-01` | Candidata, pendiente de medir |
| Autenticación y exposición de servidores | No sé | Sí: caso `auth-01` | Pendiente |
| Del exploit al test de regresión | No en los cinco proyectos revisados (solo README y código leído en parte) | Sí, una vez exista el validador | Candidata fuerte, depende del MVP |
| Benchmark público de escáneres de MCP | No sé; pendiente de buscar en papers | No (es un entregable, no un caso) | Pendiente |
| Permisos y secretos | Parcial: Cisco, Snyk y MCP-Shield a nivel de metadatos; MCPSafetyScanner a nivel de entorno | Sí | Pendiente |

## Diferenciación (hipótesis a validar con el benchmark)

Lynceus se diferencia en: (1) reportar solo fallos de implementación **confirmados con una reproducción** en un sandbox; ninguno de los cinco proyectos revisados lo describe, y MCPSafetyScanner, que usa agentes, no contiene paso de verificación en el código visto; (2) cubrir clases que el SAST de patrón no ve o no distingue (path traversal, SSRF, autorización con fallo abierto); (3) publicar un benchmark con métricas comparables. La inyección de comandos no es un argumento de detección: ya está cubierta. Supuestos sin verificar: CodeQL y el modo behavioral de Cisco.