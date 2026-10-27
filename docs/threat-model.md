# Modelo de amenazas de Lynceus (borrador v0.1)

Estado: borrador del autor, sin revisión externa. Ámbito: servidores MCP escritos en Python, ejecutados por stdio, en el MVP (v1).

## 1. Qué protege Lynceus y de qué

Lynceus recibe el código de un servidor MCP, lo ejecuta en un entorno aislado, lanza entradas de ataque contra sus herramientas y reporta solo los fallos que consigue reproducir, con evidencia.

Activos a proteger, por orden de importancia:
1. La máquina y las credenciales de quien ejecuta Lynceus.
2. La integridad de los resultados (que un informe no se pueda falsear).
3. Terceros: ningún ataque debe salir del entorno aislado hacia otras máquinas.

## 2. Clases de fallo del MVP

Cada clase se confirma con un canario: una señal que crea Lynceus y que solo aparece si el fallo es real.

### 2.1 Inyección de comandos y de argumentos (CWE-77, 78, 88)
- Qué es: un parámetro de la herramienta llega a un shell o a la línea de comandos de un programa sin neutralizar. La inyección de argumentos es la variante en la que el valor, sin usar shell, se interpreta como una opción (por ejemplo, un valor que empieza por un guion).
- Casos del benchmark: cmdi-01-vulnerable y cmdi-01-fixed.
- Canario: la entrada pide crear un fichero marcador con nombre aleatorio dentro del entorno aislado; el fallo se confirma si el fichero existe después.
- Límite: una validación parcial puede bloquear la carga útil de prueba y dejar abierta otra variante. Un resultado negativo no demuestra ausencia de fallo.

### 2.2 SSRF (CWE-918)
- Qué es: un parámetro controla a qué dirección hace una petición el servidor.
- Casos del benchmark: ssrf-01-vulnerable y ssrf-01-fixed.
- Canario: un receptor local que arranca Lynceus dentro del entorno aislado; el fallo se confirma si recibe una petición con un identificador aleatorio.
- Límite: el caso corregido asume hosts permitidos de confianza y que no hay redirecciones hacia hosts internos. Habrá que añadir variantes con redirección y con resolución de nombres.

### 2.3 Path traversal (CWE-22)
- Qué es: un parámetro permite leer o escribir fuera del directorio previsto.
- Casos del benchmark: ptrav-01-vulnerable y ptrav-01-fixed.
- Canario: Lynceus coloca un fichero con un contenido aleatorio fuera del directorio permitido; el fallo se confirma si ese contenido aparece en la respuesta de la herramienta.
- Límite: enlaces simbólicos, codificaciones y rutas absolutas son variantes distintas que hay que probar por separado.

## 3. Amenazas de ejecutar un servidor no confiable

Se asume que el servidor analizado puede ser malicioso o estar comprometido, aunque el uso previsto sea sobre código propio.

| Amenaza | Impacto | Control previsto |
|---|---|---|
| El servidor lee ficheros del anfitrión (claves SSH, variables de entorno, historial) | Robo de credenciales | Sin montajes del anfitrión salvo una copia de solo lectura del código; sin variables de entorno heredadas; usuario sin privilegios dentro del contenedor |
| El servidor abre conexiones a internet o a la red local | Exfiltración, ataque a terceros | Sin red por defecto; red interna aislada que solo contiene el receptor canario |
| Escape del contenedor | Control del anfitrión | Capacidades eliminadas, perfil seccomp, sistema de ficheros de solo lectura, sin socket de Docker dentro; en producción valorar aislamiento reforzado (por ejemplo gVisor o máquinas virtuales ligeras, sin verificar su viabilidad en macOS) |
| Consumo excesivo de CPU, memoria, procesos o disco | Denegación de servicio en la máquina | Límites de recursos y tiempo máximo por ejecución |
| Falsificación de resultados: el servidor finge que el canario ha funcionado | Falsos positivos o informes manipulados | El oráculo vive fuera del objetivo: Lynceus crea y comprueba los canarios, nunca confía en lo que el servidor diga que hizo |
| Servidor que detecta que lo analizan y se comporta distinto | Falsos negativos | Documentar la limitación; variar entradas e identidad de cliente |
| Instalación de dependencias con código malicioso | Ejecución en la fase de construcción | Separar construcción y ejecución; construir con red limitada y dependencias fijadas; ejecutar sin red |
| Persistencia entre ejecuciones | Contaminación de análisis posteriores | Entorno efímero que se destruye tras cada análisis |
| Inyección de instrucciones en las respuestas si Lynceus usa un LLM para generar entradas o interpretar salidas | El servidor manipula al agente | El LLM nunca ejecuta nada en el anfitrión; sus salidas son propuestas que pasan por el validador; el veredicto lo da el canario, no el LLM |
| Fuga de datos hacia un proveedor de LLM | Código ajeno enviado a terceros | Documentar qué se envía; permitir modelos locales |

## 4. Fuera de alcance en v1

- Autenticación, origen y autorización en servidores HTTP (v2).
- Inyección de instrucciones en descripciones de herramientas y tool poisoning: ya cubiertos por otras herramientas.
- Cadena de suministro y malware en dependencias.
- Denegación de servicio como clase de fallo del objetivo.
- Servidores en lenguajes distintos de Python.

## 5. Uso responsable

- Solo contra código propio o con autorización expresa. Nunca contra servidores de terceros en ejecución.
- Si se encuentra un fallo en un proyecto ajeno: divulgación responsable al mantenedor antes de publicar nada.
- Los benchmarks públicos usarán casos propios, no nombres de proyectos reales con fallos sin corregir.

## 6. Supuestos y preguntas abiertas

- El aislamiento con contenedores no es una frontera absoluta; falta decidir el nivel mínimo aceptable.
- No se ha medido qué hacen los desarrolladores de MCP hoy para probar la seguridad de sus servidores.
- Falta decidir qué sistema operativo y qué motor de contenedores son el objetivo del MVP.