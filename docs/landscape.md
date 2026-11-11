# Panorama de competidores

Fecha de la revisión: 21-27/10/2026. Fuentes: READMEs públicos, lectura parcial de código, datos del NVD y pruebas locales del autor. Lo anotado solo desde un README no está verificado en ejecución.

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

- MCP Watch: aparece en el NVD descrito como "comprehensive security scanner for MCP servers" (CVE-2025-66401). No revisado.
- Papers y benchmarks académicos de seguridad de MCP (taxonomías y posibles benchmarks públicos de escáneres).
- Servidores MCP vulnerables a propósito (corpus para el benchmark; comprobar licencia).
- promptfoo (¿tiene pruebas específicas de MCP?).
- Modo behavioral de Cisco (requiere clave LLM).
- Recuento de servidores MCP por lenguaje (decide la prioridad de un segundo adaptador).

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
- Inyección de comandos: detectada por Bandit y Semgrep (Semgrep distingue el caso corregido).
- SSRF: las reglas son de patrón y no distinguen validación de host (marcan vulnerable y corregido por igual).
- Path traversal: sin cobertura en ninguna configuración probada.

Limitaciones: n=1 por clase, casos del autor, CodeQL probado en la sección siguiente. Modo behavioral de Cisco sin probar (requiere clave LLM).

## Línea base CodeQL (27/10/2026, n=1 por clase, casos del autor)

Versiones: CodeQL CLI 2.27.3, paquete codeql/python-queries 1.8.13. Conjuntos: el de por defecto y python-security-extended.

Resultado: 0 hallazgos en los 6 casos del benchmark, incluidos los vulnerables de inyección de comandos, path traversal y SSRF, con los 6 ficheros extraídos.

Control: dos ficheros Flask fuera del repo, con parámetros de petición (request.args) hacia subprocess con shell=True, requests.get y open, generan py/command-line-injection, py/full-ssrf y py/path-injection. La herramienta y la configuración funcionan con fuentes que CodeQL conoce.

Lectura (hipótesis respaldada en las tres clases, no probada): CodeQL no reconoce los parámetros de las herramientas MCP como fuentes no confiables, así que el dato nunca queda marcado como contaminado. Un detector específico de MCP debe tratarlos como fuente. No se ha probado a añadir un modelo de fuentes a CodeQL.

Limitaciones: n=1 por clase, casos del autor, versión concreta de las consultas, y resultado válido solo para Python.

Licencia (lectura propia, no asesoramiento legal): los términos del CLI permiten investigación académica y análisis de código abierto (OSI) en local, y prohíben analizar código no abierto sin licencia de GitHub Advanced Security y distribuir, integrar u ofrecer el software como servicio alojado. Conclusión: usable como línea base del benchmark (repo público, Apache-2.0), no como componente de Lynceus.

## Prueba de reglas taint propias (Semgrep, 29/10/2026, n=1 por clase, casos del autor)

Reglas: `rules/semgrep/mcp-taint.yaml` (3 reglas, escritas por el autor). La fuente son los parámetros de las funciones decoradas con `@x.tool()`; los sumideros dependen de la clase (shell, ficheros, peticiones).

Resultado: 4 hallazgos en 6 casos. Detecta los 3 casos vulnerables (inyección de comandos, path traversal y SSRF), deja limpios cmdi-01-fixed y ptrav-01-fixed y marca ssrf-01-fixed.

Lectura: declarar los parámetros de las herramientas MCP como fuente no confiable basta, en estos casos, para detectar el path traversal que ninguna configuración anterior detectaba. El falso positivo de ssrf-01-fixed se debe a que la validación se hace sobre parsed.hostname y no sobre la URL: es el tipo de candidato que debe descartar la confirmación dinámica (un canario que no recibe ninguna petición).

Limitaciones: las reglas y los casos los escribió la misma persona, conociéndolos; n=1 por clase; sin variantes de elusión (rutas absolutas, enlaces simbólicos, redirecciones). Los sanitizadores por efecto lateral son permisivos (cualquier llamada a fullmatch o is_relative_to cuenta como validación aunque no se use su resultado) y pueden provocar falsos negativos. No es una tasa de detección.

## Benchmark ampliado (30/10/2026, 24 casos, Semgrep 1.183.0)

18 casos nuevos escritos sin acceso a las reglas, más los 6 iniciales. Evaluación con `scripts/eval_semgrep.py` y `rules/semgrep/mcp-taint.yaml`.

| Clase | TP | FP | FN | Precisión | Recall |
|---|---|---|---|---|---|
| Inyección de comandos | 1 | 0 | 3 | 1,00 | 0,25 |
| Path traversal | 3 | 1 | 1 | 0,75 | 0,75 |
| SSRF | 2 | 1 | 2 | 0,67 | 0,50 |
| Global | 6 | 2 | 6 | 0,75 | 0,50 |

Lectura: los falsos negativos vienen de sumideros no cubiertos (os.system, asyncio.create_subprocess_shell, inyección de argumentos sin shell), de flujo entre funciones auxiliares y de flujo entre herramientas mediante estado. Los falsos positivos, de validaciones que la regla no reconoce (listas de permitidos). Algunos casos corregidos salen limpios porque usan sumideros no modelados, no porque la validación se reconozca: la precisión sobre corregidos está inflada por puntos ciegos.

Conclusión: el análisis estático por reglas cubre el flujo directo, pero no el flujo entre funciones ni entre herramientas. La validación dinámica, que no depende del flujo, pasa a ser la prioridad. Estos 18 casos ya se han visto: la cifra publicable requerirá un lote nuevo no usado para ajustar.

## Validación dinámica: inyección de comandos (30/10/2026, 8 casos)

Sandbox Docker endurecido (sin red, sistema de ficheros de solo lectura, /tmp limitado y sin ejecución, sin capacidades ni privilegios, límites de procesos, memoria y CPU). Herramientas y parámetros descubiertos con list_tools; 7 técnicas de carga fijas, con y sin prefijo inocuo; un servidor nuevo por intento; canario en /tmp comprobado por el harness.

| Método | TP | FP | FN | Precisión | Recall |
|---|---|---|---|---|---|
| Reglas de Semgrep | 1 | 0 | 3 | 1,00 | 0,25 |
| Validación dinámica | 3 | 0 | 1 | 1,00 | 0,75 |

Lectura: la validación dinámica confirma cmdi-02 (os.system en una función auxiliar) y cmdi-04 (create_subprocess_shell en una herramienta asíncrona), que las reglas no veían, sin marcar ningún caso corregido. El falso negativo es cmdi-03, inconcluso porque el caso necesita un repositorio en /repo que el sandbox no tiene.

Limitaciones: 8 casos (4 vulnerables), una sola clase, casos escritos por un agente. El canario lo comprueba el harness, dentro del mismo contenedor que el servidor: un servidor malicioso podría fingir un positivo. Los errores de entorno se detectan por texto. Un error de transporte puntual (BrokenResourceError) no se reintenta.

## Validación dinámica: path traversal (30/10/2026, 8 casos)

Mismo sandbox y mismo harness que en inyección de comandos. Canario de lectura: antes de cada intento se crea en /tmp un fichero con nombre y contenido aleatorios e independientes; el intento se confirma solo si el contenido aparece en la respuesta de la herramienta. Tres técnicas fijas: ruta absoluta, `../` repetido y la misma con prefijo `./`.

| Método | TP | FP | FN | Precisión | Recall |
|---|---|---|---|---|---|
| Reglas de Semgrep | 3 | 1 | 1 | 0,75 | 0,75 |
| Validación dinámica | 4 | 0 | 0 | 1,00 | 1,00 |

Lectura: la validación dinámica confirma ptrav-02 (sumidero en una función auxiliar), que las reglas no veían, y deja limpio ptrav-03-fixed (lista de permitidos), que las reglas marcaban como falso positivo. ptrav-04-vulnerable solo se confirma con la ruta absoluta, porque su filtro bloquea `..`: la cobertura depende de tener varias técnicas.

Limitaciones: 8 casos (4 vulnerables), escritos por un agente; la predicción previa se cumplió exactamente, lo que sugiere casos sencillos. En esta clase, FileNotFoundError cuenta como respuesta normal y solo ModuleNotFoundError y los fallos de infraestructura cuentan como inconclusos; otros errores de entorno (por ejemplo, PermissionError) se clasificarían como no confirmados. Mismo límite del oráculo: lo comprueba el harness dentro del contenedor.

## Observación pendiente de verificar: procesos hijo y stdio

En cmdi-02-vulnerable, el intento con `lynceus && touch <canario>` termina siempre en BrokenResourceError (no es transitorio). Hipótesis: el comando resultante ejecuta `grep lynceus` sin fichero, que lee de la entrada estándar; en un servidor MCP por stdio esa entrada es el canal del protocolo, así que grep consume los mensajes y rompe el transporte. Si se confirma, un proceso hijo que hereda la entrada estándar de un servidor MCP por stdio puede corromper el protocolo, lo que sería una vía de denegación de servicio.

Rendimiento: la validación de inyección de comandos tarda unos 3,5 minutos en 8 casos (unos 2 segundos por intento, por arrancar un servidor nuevo en cada uno). Pendiente: paralelizar o reutilizar el contenedor, y matar el contenedor también ante una interrupción.

## Validación dinámica: SSRF (01/11/2026, 8 casos)

Por cada caso, una red Docker interna (sin salida) creada y borrada en cada ejecución, con dos contenedores endurecidos: el servidor y un receptor HTTP mínimo que registra cada petición. Antes de los intentos, un contenedor efímero comprueba que no hay salida TCP ni resolución DNS externa; si la hay, la validación aborta (fallo cerrado). El oráculo lee el registro del receptor desde fuera: por primera vez, el servidor no puede fingir un positivo. Tres técnicas: URL con el nombre del receptor, con su IP, y `file://` con canario de lectura. Intentos en dos pasos: tras la llamada con la carga, se llama a las demás herramientas reutilizando por nombre los valores de la primera llamada.

| Método | TP | FP | FN | Precisión | Recall |
|---|---|---|---|---|---|
| Reglas de Semgrep | 2 | 1 | 2 | 0,67 | 0,50 |
| Validación dinámica | 4 | 0 | 0 | 1,00 | 1,00 |

Lectura: ssrf-01-fixed, el falso positivo de las reglas que originó la tesis del proyecto, queda descartado porque el receptor no recibe ninguna petición. ssrf-03-vulnerable (una herramienta guarda la URL y otra hace la petición) se confirma gracias a los dos pasos. `file://` confirma ssrf-01 y ssrf-04, donde la SSRF permite además leer ficheros locales.

Limitaciones: 8 casos (4 vulnerables), escritos por un agente. El receptor se da por listo cuando su contenedor está en marcha, no cuando acepta conexiones. La comprobación de aislamiento es puntual, antes de los intentos. El token solo se busca en la ruta de la petición. ssrf.py reutiliza funciones privadas de ptrav.py, pendientes de pasar a un módulo común.

## Primer servidor real: CVE-2026-7400 (02/11/2026)

Objetivo: geekgod382/filesystem-mcp-server, servidor Python por stdio con el servidor de bajo nivel del SDK y diez herramientas. La versión 1.0.0 comprueba `abspath(path).startswith(home)`, sin resolver enlaces ni exigir separador; la 1.1.0 (commit 4536454) usa `realpath` y añade el separador.

Primer intento: Lynceus marcó las dos versiones. Causa: el sandbox definía HOME=/tmp, el servidor usa el directorio personal como límite y el canario estaba en /tmp, dentro del límite. Era un falso positivo en la versión corregida: el oráculo de path traversal daba por hecho que /tmp quedaba fuera de cualquier límite, algo cierto en el benchmark propio pero no en un servidor real.

Corrección: límite declarado (por defecto /tmp/lynceus-root, que pasa a ser el HOME del sandbox; configurable con --fs-root) y canarios siempre fuera de él, en tres formas: una carpeta aparte, una carpeta hermana con el mismo prefijo y un enlace simbólico dentro del límite que apunta fuera. Un control positivo informativo comprueba que cada herramienta lee dentro del límite.

| Versión | Antes | Después |
|---|---|---|
| 1.0.0 (vulnerable) | Confirmada | Confirmada: carpeta hermana (ruta absoluta y `../`) y enlace simbólico |
| 1.1.0 (corregida) | Confirmada (falso positivo) | Sin hallazgos |

Lectura: es la primera vulnerabilidad real reproducida por Lynceus y distinguida de su corrección, sin adaptar nada al servidor. El benchmark propio no podía revelar este fallo del oráculo: sus casos son más sencillos que un servidor real.

Limitaciones: un solo CVE. Si el servidor usa un límite distinto de su directorio personal, hay que declararlo. Unos 95 segundos por versión (un servidor nuevo por intento). El control positivo lista todos los parámetros, aunque la mayoría de herramientas no devuelven contenido.

## Índices de confianza para servidores MCP (03/11/2026)

Existen varios índices comerciales que puntúan servidores MCP (M8ven, CraftedTrust, Canopii, Dominion Observatory, entre otros). M8ven indexó este repositorio por su cuenta y analizó sus 64 archivos Python en el commit e1fcf71: 74/100, "No concerning findings". Sus comprobaciones públicas cubren exfiltración de credenciales, acceso a ficheros sensibles y ofuscación, y la nota la limita sobre todo la reputación (estrellas, colaboradores y antigüedad).

Lectura: el repositorio contiene 12 servidores MCP vulnerables a propósito (inyección de comandos con shell=True y os.system, path traversal y SSRF) y el resumen público no señala ninguno. Indica que este tipo de índice se centra en servidores maliciosos y en señales de reputación, no en fallos de implementación explotables, que es el problema que aborda Lynceus.

Limitaciones: un solo índice; su auditoría completa solo está disponible para quien reclama la ficha y podría contener más; también clasificó Lynceus como servidor MCP y le atribuyó las herramientas de los casos del benchmark.

## Segundo servidor real: CVE-2026-7812 (03/11/2026)

Objetivo: 54yyyu/code-mcp, servidor Python con FastMCP y nueve herramientas, sin versión corregida. Su git_operation ejecuta `git {operation}` en una shell. Para analizarlo hicieron falta tres piezas nuevas: el punto de entrada configurable (arranca con main.py e importa el paquete desde src/), un entorno propio (está escrito para el SDK de MCP de marzo de 2025 y falla con el 1.30 del sandbox) y la sonda de capacidad.

Entorno: lynceus build resolvió las dependencias a la fecha de su último commit (SDK 1.5.0) en un contenedor con red, descargó solo paquetes precompilados con hash y construyó la imagen sin red. El harness sigue con su propio SDK 1.30 en la misma imagen, y la conexión entre ambas versiones funcionó. La resolución es reproducible: repetida, produce la misma imagen.

Resultado: git_operation, vulnerabilidad crítica confirmada con 10 técnicas. run_command, clasificada como capacidad, porque la sonda `touch <canario>` sin metacaracteres se ejecuta: la herramienta ejecuta comandos por diseño. Ningún hallazgo en las otras siete herramientas. Unos 220 segundos.

Observación: run_command intenta limitarse a un comando simple con una lista negra de operadores (`;`, `&&`, `||`, `>`, `|`, `<`), y el salto de línea, `$(...)` y las comillas invertidas la eluden. Como ya ejecuta cualquier comando, el impacto adicional es pequeño, pero es un patrón que merece señalarse: una capacidad con un filtro eludible.

Limitaciones: sin versión corregida, este caso mide la detección pero no la capacidad de distinguir una corrección.

## Tercer servidor real: SSRF en mcp-server-fetch, issue #4838 (04/11/2026)

**Corrección (11/11/2026):** una versión anterior de esta sección atribuía este fallo al CVE-2025-65513. Es incorrecto: según NVD, ese CVE corresponde a otro proyecto, zcaceres/fetch-mcp (Node, versiones hasta la 1.0.2). La atribución errónea procedía de un artículo secundario que no se contrastó con NVD. El fallo de modelcontextprotocol/servers no tiene CVE: se reportó y corrigió como el issue #4838 (commit 315ad50). El análisis y sus resultados no cambian; solo el identificador. Desde esta corrección, los manifiestos de la suite real exigen la URL del aviso de cada caso, y los resultados esperados se toman de ese aviso y del código, nunca de la salida de Lynceus.

Objetivo: modelcontextprotocol/servers, src/fetch. Vulnerable: commit 9a4d513 (30/03/2025), sin ninguna comprobación de la dirección de destino. Corregida: 2026.10.10 (commit 3423e57), que rechaza por defecto direcciones privadas, de loopback y de metadatos (commit 315ad50). Las dependencias se declaran en pyproject.toml.

Entornos: dependencias resueltas a la fecha de cada commit (SDK de MCP 1.6.0 y 2.3.0). La corregida consulta su propia versión instalada al importarse; como el proyecto no se instala (construirlo ejecutaría su backend de construcción), lynceus build genera solo sus metadatos mínimos a partir del pyproject.toml, con nombre y versión validados.

Resultado: la vulnerable, confirmada con host_url e ip_url (17 segundos); la corregida, sin hallazgos ni inconclusos (8,5 segundos). El harness, con el SDK 1.30, se comunica con un servidor del SDK 2.3.0 sin problemas.

Problemas de Lynceus que destapó este caso, ya corregidos: un pyproject.toml como entrada se leía como lista de requisitos; la etiqueta de la imagen dependía de comentarios del fichero resuelto y no cubría todo el contenido de la imagen; los tests escribían en la caché real del usuario; y el contenedor de resolución guardaba su caché en un /tmp de 16 MB.

Limitaciones: en SSRF no hay control positivo. Sin salida a Internet, no se puede comprobar que la versión corregida siga descargando URL públicas: el resultado negativo es el esperado, pero no se verifica que la herramienta funcione.

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

- Bien cubierto: metadatos, prompt injection y tool poisoning (Cisco, Snyk, MCP-Shield, según sus READMEs); cadena de suministro (Cisco); control en ejecución (mcp-context-protector); detección de inyección de comandos (Bandit y Semgrep; CodeQL no la ve en servidores MCP).
- Mal cubierto: SSRF (reglas de patrón que no distinguen una validación real).
- No encontrado en lo revisado: path traversal en servidores MCP (ni Bandit, ni Semgrep, ni CodeQL); autorización con fallo abierto; y verificación de cada hallazgo con una reproducción. Esto último, ninguno de los cinco proyectos lo describe ni lo muestra en el código leído, pero la revisión es parcial.

## Evidencia: CVE publicados (NVD, 25/10/2026)

Muestra: 524 CVE únicos que mencionan "model context protocol" o "mcp server", 38 de ellos de SDK. Incluye también clientes y frameworks, no solo servidores. Un CVE puede contar en varias clases y no se midió cuántos carecen de CWE. Cifras orientativas.

| Clase | CVE | % |
|---|---|---|
| Inyección de comandos, argumentos y código | 110 | 21 % |
| Autenticación y origen | 93 | 18 % |
| SSRF | 91 | 17 % |
| Autorización | 57 | 11 % |
| Ruta y ficheros | 52 | 10 % |
| Denegación de servicio | 19 | 4 % |

Lecturas:
- La inyección de comandos y argumentos es la clase más frecuente: el valor de Lynceus ahí es confirmar con una ejecución, no detectar.
- Autenticación, origen y autorización suman hasta unos 150 CVE y dependen del despliegue (HTTP): candidatas a v2, con ventaja sobre el análisis estático.
- Herramientas de prueba y escáneres con CVE propios (MCP Inspector, MCPJam Inspector, MCP Watch): ejecutar siempre en sandbox.

## Direcciones evaluadas

| Dirección | Cubierta por alguien (sí/no/no sé) | Medible con un caso (sí/no) | Veredicto |
|---|---|---|---|
| Inyección de comandos y argumentos con confirmación dinámica | Detección sí (Bandit, Semgrep); confirmación no vista en los cinco proyectos | Sí (cmdi-01) | v1 |
| SSRF y path traversal con confirmación dinámica | Detección parcial o nula (Bandit, Semgrep, CodeQL) | Sí (ssrf-01, ptrav-01) | v1 |
| Modelo de fuentes y sumideros específico de MCP (parámetro de herramienta como fuente no confiable) | No en lo probado: ni Bandit, ni Semgrep ni CodeQL lo modelan | Probado con los 6 casos: detecta los 3 vulnerables y marca 1 corregido | v1, pieza técnica central; falta medir con variantes de elusión |
| Autenticación, origen y autorización sobre HTTP | No sé; el análisis estático apenas la ve | Sí (auth-01, authz-01), con otro banco de pruebas | v2, alta prioridad de mercado |
| Del exploit al test de regresión | No en los cinco proyectos revisados | Sí, cuando exista el validador | Candidata fuerte |
| Benchmark público de escáneres de MCP | No sé; pendiente de buscar en papers | No (entregable) | Pendiente |
| Permisos y secretos | Parcial a nivel de metadatos | Sí | Baja prioridad |

## Diferenciación (hipótesis a validar con el benchmark)

Lynceus se diferencia en: (1) reportar solo fallos de implementación confirmados con una reproducción en un sandbox (ninguno de los cinco proyectos revisados lo describe; MCPSafetyScanner, que usa agentes, no contiene paso de verificación en el código visto); (2) cubrir clases que el SAST no ve o no distingue (path traversal, SSRF, autorización con fallo abierto), tratando los parámetros de las herramientas MCP como fuentes no confiables, algo que ni Bandit, ni Semgrep ni CodeQL hacen en lo probado; (3) publicar un benchmark con métricas comparables.

La inyección de comandos es la clase más frecuente en los CVE y Bandit y Semgrep la detectan: ahí el valor es la confirmación, no la detección.

Supuestos sin verificar: el modo behavioral de Cisco; que CodeQL no vea los casos por falta de fuentes MCP (hipótesis respaldada por controles, no probada); y que los desarrolladores de MCP no usen hoy herramientas de SAST (requiere hablar con ellos).