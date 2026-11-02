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

## Uso

### Instalación (desde el código fuente)

Requisitos: Python 3.12, [uv](https://docs.astral.sh/uv/) y Docker.

```bash
git clone https://github.com/acanellada/Lynceus.git
cd Lynceus
uv sync
```

`uv sync` crea el entorno virtual y resuelve las dependencias fijadas en `uv.lock`. No hay paquete publicado en PyPI: el comando `lynceus` se ejecuta con `uv run lynceus ...` o, dentro del entorno activado, directamente como `lynceus ...`.

### Imagen del sandbox

La validación dinámica ejecuta el servidor analizado dentro de un contenedor Docker endurecido. Antes de usar `lynceus scan` o `lynceus bench` hay que construir esa imagen una vez:

```bash
docker build -t lynceus-sandbox:0.1 sandbox/
```

### `lynceus scan`

Valida dinámicamente una carpeta con `server.py` (mismo formato que un caso del benchmark):

```bash
uv run lynceus scan ./mi-servidor-mcp
uv run lynceus scan ./mi-servidor-mcp --classes ssrf --classes path_traversal
uv run lynceus scan ./mi-servidor-mcp --json out.json --report out.html
```

### `lynceus bench`

Ejecuta la validación dinámica sobre `benchmark/cases` y muestra las métricas (precisión y recall) por clase y globales:

```bash
uv run lynceus bench
uv run lynceus bench --classes command_injection
```

### Opciones

| Opción | Comandos | Descripción |
|---|---|---|
| `--classes` | `scan`, `bench` | Clase a incluir (repetible): `command_injection`, `path_traversal`, `ssrf`. Por defecto, las tres. |
| `--json` | `scan` | Ruta donde escribir el informe en JSON. |
| `--report` | `scan` | Ruta donde escribir el informe HTML autónomo (sin JavaScript ni recursos externos). |
| `--plain` | `scan`, `bench` | Salida de texto plano, sin colores, emojis ni ajuste de línea de rich: estable para `grep` o CI. |

### Códigos de salida (`lynceus scan`)

- `0`: validación completada, sin hallazgos confirmados.
- `1`: validación completada, con uno o más hallazgos confirmados.
- `2`: error (argumentos inválidos, carpeta u objetivo inválido, o fallo del entorno de validación, p. ej. Docker no disponible).

### Salida no interactiva

`lynceus` detecta automáticamente cuándo debe usar texto plano, sin necesidad de `--plain`: si la variable de entorno `NO_COLOR` está definida, o si la salida estándar no es una terminal interactiva (por ejemplo, al redirigir a un fichero o a una tubería), se desactivan colores, emojis y el ajuste de línea de rich.

![Ejemplo de `lynceus scan`](docs/img/lynceus-scan.png)

## Uso responsable

Utilízalo solo contra sistemas propios o con autorización expresa. Los casos del benchmark son vulnerables a propósito: no los expongas a una red ni los ejecutes fuera del sandbox.

## Licencia

Apache-2.0.
