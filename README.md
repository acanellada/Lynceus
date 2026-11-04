<p align="center">
  <img src="docs/img/banner.png" alt="Lynceus: validador de seguridad para servidores MCP" width="100%">
</p>

<p align="center">
  <img src="https://github.com/acanellada/Lynceus/actions/workflows/ci.yml/badge.svg" alt="CI">
  <img src="https://img.shields.io/badge/licencia-Apache--2.0-f5a524" alt="Licencia Apache-2.0">
  <img src="https://img.shields.io/badge/python-3.12-f5a524" alt="Python 3.12">
  <img src="https://img.shields.io/badge/estado-en%20desarrollo-8f97a6" alt="Estado: en desarrollo">
</p>

Lynceus analiza servidores MCP (Model Context Protocol) y **solo reporta los fallos de implementación que consigue reproducir** dentro de un sandbox aislado, con la evidencia y la llamada exacta que los reproduce.

> **Estado:** en desarrollo (v0.1.0). Se instala desde el código fuente; no está publicado en PyPI.

<p align="center">
  <img src="docs/img/lynceus-scan.png" alt="Ejemplo de lynceus scan confirmando una SSRF" width="100%">
</p>

## Por qué

Los servidores MCP exponen herramientas que un agente de IA invoca con parámetros que pueden venir de contenido no confiable: una página web, un documento o una inyección de prompt. Si una herramienta usa esos parámetros en un comando, una ruta de fichero o una URL sin validarlos, el atacante controla el servidor.

- De 524 CVE únicos relacionados con MCP en NVD (25/10/2026), las clases más frecuentes son inyección de comandos (21 %), autenticación y origen (18 %), SSRF (17 %), autorización (11 %) y path traversal (10 %).
- Los analizadores estáticos generalistas no tratan los parámetros de las herramientas MCP como entrada no confiable: CodeQL no detectó ninguno de los casos vulnerables iniciales del benchmark.
- Las reglas estáticas que sí lo hacen generan falsos positivos cuando no entienden la validación. Un canario que no se activa los descarta.

## Cómo funciona

```mermaid
flowchart LR
    A[Servidor MCP] -->|list_tools| B[Descubre herramientas y parámetros]
    B --> C[Genera cargas con canarios únicos]
    C --> D[Las ejecuta en un sandbox Docker endurecido]
    D --> E{¿El oráculo observa el canario?}
    E -->|Sí| F[Vulnerabilidad confirmada, con reproducción]
    E -->|No| G[No confirmada]
```

| Clase | Canario | Oráculo |
|---|---|---|
| Inyección de comandos | Fichero con nombre aleatorio que solo crea un comando inyectado | El fichero existe tras la llamada |
| Path traversal | Fichero fuera del directorio permitido, con contenido aleatorio | El contenido aparece en la respuesta |
| SSRF | Receptor HTTP en una red interna sin salida | El receptor recibe la petición con el token del intento |

Las herramientas y los parámetros se descubren con `list_tools`, como con cualquier servidor desconocido: nada está adaptado a casos concretos. Cada intento arranca un servidor nuevo, y en SSRF se prueban también flujos en dos pasos (una herramienta guarda la URL y otra la usa).

## Resultados

Benchmark propio de 24 casos (8 por clase, 4 vulnerables y 4 corregidos), comparando reglas taint de Semgrep con la validación dinámica:

| Clase | Reglas de Semgrep (precisión / recall) | Validación dinámica (precisión / recall) |
|---|---|---|
| Inyección de comandos | 1,00 / 0,25 | 1,00 / 0,75 |
| Path traversal | 0,75 / 0,75 | 1,00 / 1,00 |
| SSRF | 0,67 / 0,50 | 1,00 / 1,00 |
| **Global** | **0,75 / 0,50** | **1,00 / 0,92** |

El único falso negativo de la validación dinámica es un caso inconcluso por su entorno (`cmdi-03`). **Cautela:** los casos los escribió un agente de código y ya se han usado durante el desarrollo, así que estas cifras no son una medida independiente. El detalle, la metodología y las limitaciones están en [`docs/landscape.md`](docs/landscape.md).

### Primer servidor real: CVE-2026-7400

`filesystem-mcp-server` (geekgod382) limita el acceso al directorio personal comparando `abspath(path).startswith(home)`, sin resolver enlaces simbólicos ni exigir un separador. Lynceus, sin ninguna adaptación a este servidor:

| Versión | Resultado |
|---|---|
| 1.0.0 (vulnerable) | Confirmada: carpeta hermana con el mismo prefijo y enlace simbólico |
| 1.1.0 (corregida) | Sin hallazgos |

Este caso destapó un falso positivo en la versión anterior de Lynceus (el canario quedaba dentro del límite del servidor), corregido con canarios conscientes del límite.

### Segundo servidor real: CVE-2026-7812

`code-mcp` (54yyyu) concatena el parámetro `operation` de `git_operation` a un comando `git` que se ejecuta en una shell. Está escrito para una versión antigua del SDK de MCP, así que Lynceus construye su entorno con las dependencias resueltas a la fecha de su último commit (SDK 1.5.0), en una imagen aparte del harness.

| Herramienta | Resultado |
|---|---|
| `git_operation` | Vulnerabilidad crítica confirmada (10 técnicas) |
| `run_command` | Capacidad por diseño: ejecuta comandos a propósito, así que no se reporta como inyección |
| Las otras siete | Sin hallazgos |

### Tercer servidor real: CVE-2025-65513

`mcp-server-fetch`, el servidor de referencia oficial para descargar páginas web, no comprobaba a qué dirección se conectaba. La versión de octubre de 2026 rechaza por defecto las IP privadas, de loopback y de metadatos. Cada versión se analiza con su propio entorno: la vulnerable con el SDK de MCP 1.6.0 y la corregida con el 2.3.0.

| Versión | Resultado |
|---|---|
| Marzo de 2025 (vulnerable) | SSRF confirmada: el receptor recibió la petición por nombre y por IP |
| 2026.10.10 (corregida) | Sin hallazgos |

Con este caso, Lynceus ha reproducido un CVE real de cada una de sus tres clases, y en dos de ellos ha distinguido la versión vulnerable de su corrección.

## Inicio rápido

Requisitos: Python 3.12, [uv](https://docs.astral.sh/uv/) y Docker.

```bash
git clone https://github.com/acanellada/Lynceus.git
cd Lynceus
uv sync
docker build -t lynceus-sandbox:0.1 sandbox/
uv run lynceus scan benchmark/cases/ssrf-03-vulnerable --report informe.html
```

## Uso

### `lynceus scan`

Valida dinámicamente una carpeta con `server.py` (por ahora, el mismo formato que un caso del benchmark):

```bash
uv run lynceus scan ./mi-servidor-mcp
uv run lynceus scan ./mi-servidor-mcp --classes ssrf --classes path_traversal
uv run lynceus scan ./mi-servidor-mcp --json out.json --report out.html
```

### `lynceus build`

Construye la imagen de un servidor con sus propias dependencias. La resolución y la descarga se hacen en un contenedor aparte, con red; la imagen se construye después sin red, solo con paquetes precompilados y fijados por hash. Con `--resolve-date`, las dependencias se resuelven tal como estaban en esa fecha, para reproducir el entorno de un CVE:

```bash
uv run lynceus build ./mi-servidor --requirements requirements.txt --resolve-date 2025-03-22
uv run lynceus scan ./mi-servidor --image lynceus-target:<etiqueta> --entry main.py --pythonpath src
```

Requiere construir antes la imagen de resolución: `docker build -t lynceus-resolver:0.1 sandbox/resolver/`.

### `lynceus bench`

Ejecuta la validación dinámica sobre `benchmark/cases` y muestra la precisión y el recall por clase y globales:

```bash
uv run lynceus bench
uv run lynceus bench --classes command_injection
```

### Opciones

| Opción | Comandos | Descripción |
|---|---|---|
| `--classes` | `scan`, `bench` | Clase a incluir (repetible): `command_injection`, `path_traversal`, `ssrf`. Por defecto, las tres. |
| `--json` | `scan` | Ruta donde escribir el informe en JSON (con `schema_version`). |
| `--report` | `scan` | Ruta donde escribir el informe HTML autónomo, sin JavaScript ni recursos externos. |
| `--plain` | `scan`, `bench` | Texto plano, sin colores ni emojis: estable para `grep` o CI. |
| `--fs-root` | `scan` | Límite de sistema de ficheros para path traversal, bajo `/tmp`. Por defecto, `/tmp/lynceus-root`, que también es el directorio personal del servidor en el sandbox. |
| `--entry` | `scan` | Fichero con el que arranca el servidor, relativo a la carpeta. Por defecto, `server.py`. |
| `--pythonpath` | `scan` | Carpeta (relativa, repetible) que se añade al `PYTHONPATH` del servidor. |
| `--image` | `scan` | Imagen creada con `lynceus build`, con las dependencias del servidor. |

### Códigos de salida de `lynceus scan`

- `0`: validación completada, sin vulnerabilidades confirmadas.
- `1`: validación completada, con una o más vulnerabilidades confirmadas.
- `2`: error (argumentos o carpeta no válidos, o fallo del entorno de validación, por ejemplo, Docker no disponible).

El formato se desactiva solo si existe la variable `NO_COLOR` o si la salida no es una terminal interactiva (al redirigirla a un fichero o a una tubería).

## Seguridad del sandbox

El servidor analizado es código no confiable. Lynceus lo ejecuta siempre dentro de un contenedor con estas protecciones:

- Sin red (`--network none`), o en SSRF, una red Docker interna creada para cada caso y borrada al terminar. Antes de los intentos se comprueba que no hay salida TCP ni resolución DNS externa; si la hay, la validación se aborta.
- Sistema de ficheros de solo lectura, `/tmp` limitado a 16 MB y sin ejecución.
- Sin capacidades (`--cap-drop ALL`), `no-new-privileges` y usuario sin privilegios.
- Límites de procesos, memoria (sin swap) y CPU, y tiempo máximo por intento.
- El servidor y el harness montados en solo lectura; ningún puerto publicado hacia el host.
- Imagen base fijada por digest y dependencias fijadas con hash.
- Los informes tratan como no confiable todo texto que venga del servidor: se escapa en el HTML (que lleva además una política de seguridad de contenido sin scripts) y se limpia de secuencias de escape en la terminal.

El modelo de amenazas completo está en [`docs/threat-model.md`](docs/threat-model.md).

## Limitaciones

- Las dependencias del servidor solo se instalan desde paquetes precompilados: un paquete que solo exista como código fuente no se puede usar.
- Solo se prueban parámetros de tipo texto y tres clases de vulnerabilidad.
- Path traversal se evalúa respecto a un límite declarado: si el servidor usa otro límite que no sea su directorio personal, hay que indicarlo con `--fs-root`.
- En inyección de comandos y path traversal, el oráculo corre en el mismo contenedor que el servidor: un servidor malicioso podría fingir un positivo (nunca ocultar uno real). En SSRF, el oráculo es externo.
- Un servidor que bloquea las IP privadas bloquea también al receptor de SSRF, aunque su validación tenga un agujero.

## Hoja de ruta

- Un lote de servidores reales con versión vulnerable y corregida, para medir la precisión con casos reales y no solo la detección.
- Un lote de casos nuevo, no usado durante el desarrollo, para una medida independiente.
- Salida SARIF y GitHub Action.
- Distribución como skill para agentes de código, cuando haya una versión estable.

El detalle está en [`docs/roadmap.md`](docs/roadmap.md).

## Documentación

- [`docs/landscape.md`](docs/landscape.md): herramientas existentes, líneas base (Bandit, Semgrep y CodeQL), datos de CVE y resultados.
- [`docs/threat-model.md`](docs/threat-model.md): modelo de amenazas, incluido el del propio sandbox.
- [`docs/roadmap.md`](docs/roadmap.md): hoja de ruta.
- [`benchmark/README.md`](benchmark/README.md): formato y criterios de etiquetado del benchmark.

## Uso responsable

Utiliza Lynceus solo contra servidores propios o con autorización expresa. Los casos del benchmark son vulnerables a propósito: no los expongas a una red ni los ejecutes fuera del sandbox.

## Licencia

[Apache-2.0](LICENSE).
