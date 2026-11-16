"""Cargas fijas de inyección de comandos/argumentos y de path traversal. Sin LLM.

Cada carga lleva su propio canario en /tmp, comprobado por el harness, nunca
por el servidor analizado. Para inyección de comandos, cada técnica se genera
en dos variantes: "bare" (la carga sola) y "prefixed" (con un prefijo inocuo
delante, p.ej. "lynceus; touch <canario>"), porque un valor que empieza
directamente por un separador puede comportarse distinto a uno que primero
parece un valor normal.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from lynceus_sec.validator.runner import DEFAULT_FS_ROOT

_INNOCUOUS_PREFIX = "lynceus"

_TEMPLATES: dict[str, str] = {
    "shell_semicolon": "; touch {canary}",
    "shell_and": "&& touch {canary}",
    "shell_pipe": "| touch {canary}",
    "shell_newline": "\ntouch {canary}",
    "command_substitution": "$(touch {canary})",
    "backticks": "`touch {canary}`",
    "argument_injection_output": "--output={canary}",
}


@dataclass(frozen=True)
class Payload:
    technique: str
    canary_path: str
    value: str


def _random_canary_path() -> str:
    return f"/tmp/lynceus-canary-{uuid.uuid4().hex}"


def _random_canary_content() -> str:
    return f"lynceus-secret-{uuid.uuid4().hex}"


def _random_token() -> str:
    return f"lynceus-ssrf-{uuid.uuid4().hex}"


def build_payloads() -> list[Payload]:
    """Devuelve las cargas fijas, cada una con un canario nuevo y único."""
    payloads: list[Payload] = []
    for technique, template in _TEMPLATES.items():
        for variant, prefix in (("bare", ""), ("prefixed", _INNOCUOUS_PREFIX)):
            canary = _random_canary_path()
            value = prefix + template.format(canary=canary)
            payloads.append(Payload(technique=f"{technique}_{variant}", canary_path=canary, value=value))
    return payloads


def build_probe_payload() -> Payload:
    """Sonda de capacidad: el valor es exactamente "touch <canario>", sin
    metacaracteres ni prefijo inocuo delante. Si esto crea el canario, el
    parámetro no necesitó ninguna técnica de inyección: la herramienta
    ejecuta su valor como comando por diseño, no por un fallo de saneado."""
    canary = _random_canary_path()
    return Payload(technique="capability_probe", canary_path=canary, value=f"touch {canary}")


_TRAVERSAL_DEPTH = 8

# Carpeta aparte, siempre fuera de cualquier límite (`fs_root`): nombre fijo,
# conocido por el harness y por los tests; solo el contenido de cada canario
# que se planta dentro es aleatorio.
OUTSIDE_DIR = "/tmp/lynceus-outside"


@dataclass(frozen=True)
class PathPayload:
    technique: str
    canary_path: str
    canary_content: str
    value: str
    symlink_path: str | None = None
    symlink_target: str | None = None


def _sibling_dir(fs_root: str) -> str:
    """Carpeta hermana del límite, con el mismo prefijo (p.ej. /tmp/lynceus-root-x
    si el límite es /tmp/lynceus-root): detecta servidores que comprueban el
    límite con un prefijo de cadena en vez de con contención real de rutas."""
    return f"{fs_root.rstrip('/')}-x"


def build_path_traversal_payloads(
    fs_root: str = DEFAULT_FS_ROOT, depth: int = _TRAVERSAL_DEPTH
) -> list[PathPayload]:
    """Cargas de path traversal conscientes del límite (`fs_root`, el `HOME`
    del servidor analizado). Tres canarios de lectura independientes (nombre
    y contenido propios), siempre fuera del límite, en tres formas:

    - una carpeta aparte (`OUTSIDE_DIR`), con dos cargas: ruta absoluta y
      "../" repetido hasta ella (en variantes "bare" y con prefijo "./", por
      si un filtro rechaza solo las rutas que empiezan literalmente por "..");
    - una carpeta hermana del límite con el mismo prefijo (`_sibling_dir`),
      con las mismas dos cargas "bare" (absoluta y "../" repetido);
    - un enlace simbólico dentro del límite que apunta a la carpeta aparte,
      con un tercer canario independiente solo alcanzable a través de él.
    """
    traversal_prefix = "../" * depth
    payloads: list[PathPayload] = []

    outside_path = f"{OUTSIDE_DIR}/lynceus-canary-{uuid.uuid4().hex}"
    outside_content = _random_canary_content()
    outside_relative = f"{traversal_prefix}{outside_path.removeprefix('/')}"
    payloads.append(PathPayload("absolute_outside", outside_path, outside_content, outside_path))
    payloads.append(PathPayload("dotdot_outside", outside_path, outside_content, outside_relative))
    payloads.append(PathPayload("dotslash_outside", outside_path, outside_content, f"./{outside_relative}"))

    sibling_dir = _sibling_dir(fs_root)
    sibling_path = f"{sibling_dir}/lynceus-canary-{uuid.uuid4().hex}"
    sibling_content = _random_canary_content()
    sibling_relative = f"{traversal_prefix}{sibling_path.removeprefix('/')}"
    payloads.append(PathPayload("absolute_sibling", sibling_path, sibling_content, sibling_path))
    payloads.append(PathPayload("dotdot_sibling", sibling_path, sibling_content, sibling_relative))

    link_path = f"{fs_root.rstrip('/')}/lynceus-link-{uuid.uuid4().hex}"
    link_canary_name = f"lynceus-canary-{uuid.uuid4().hex}"
    link_canary_path = f"{OUTSIDE_DIR}/{link_canary_name}"
    link_content = _random_canary_content()
    payloads.append(
        PathPayload(
            "symlink", link_canary_path, link_content, f"{link_path}/{link_canary_name}",
            symlink_path=link_path, symlink_target=OUTSIDE_DIR,
        )
    )

    return payloads


@dataclass(frozen=True)
class PositiveControlPayload:
    canary_path: str
    canary_content: str
    value: str


def build_positive_control_payload(fs_root: str = DEFAULT_FS_ROOT) -> PositiveControlPayload:
    """Un fichero dentro del límite, con contenido aleatorio: control positivo
    informativo que comprueba si la misma tool/parámetro puede leer siquiera
    un fichero normal. No es una carga de ataque y nunca produce un Finding;
    solo da contexto a un resultado `not_confirmed` en las cargas de arriba.
    """
    path = f"{fs_root.rstrip('/')}/lynceus-positive-{uuid.uuid4().hex}"
    content = _random_canary_content()
    return PositiveControlPayload(canary_path=path, canary_content=content, value=path)


def _random_write_token() -> str:
    return f"lynceus-write-{uuid.uuid4().hex}"


@dataclass(frozen=True)
class WritePayload:
    """A diferencia de `PathPayload` (lectura), el harness nunca planta nada
    en `target_path`: debe no existir antes de la llamada, y solo se
    confirma si el propio servidor la crea con `token` dentro."""

    technique: str
    target_path: str
    token: str
    value: str
    symlink_path: str | None = None
    symlink_target: str | None = None


def _new_write_target(directory: str) -> str:
    return f"{directory}/lynceus-write-{uuid.uuid4().hex}"


def build_path_traversal_write_payloads(
    fs_root: str = DEFAULT_FS_ROOT, depth: int = _TRAVERSAL_DEPTH
) -> list[WritePayload]:
    """Cargas de escritura fuera del límite, conscientes de `fs_root`, en las
    mismas tres formas que `build_path_traversal_payloads` (lectura):

    - una carpeta aparte (`OUTSIDE_DIR`), con ruta absoluta y "../" repetido
      (variantes "bare" y con prefijo "./");
    - una carpeta hermana del límite con el mismo prefijo, con las mismas
      dos cargas "bare";
    - un enlace simbólico dentro del límite que apunta directamente (no a
      una carpeta, como en lectura) a una ruta aún inexistente bajo la
      carpeta aparte: un enlace "colgante". Si tras la llamada esa ruta
      existe con el token, solo pudo haberla creado el servidor siguiendo
      el enlace.

    A diferencia de la lectura (donde varias técnicas pueden compartir un
    mismo canario ya plantado, porque solo son formas distintas de llegar a
    un fichero que ya existe), aquí cada técnica lleva su propia ruta
    objetivo y su propio token: la llamada puede crear esa ruta, y si dos
    técnicas compartieran una, la primera en confirmar dejaría la ruta
    creada y la comprobación de "no debe existir todavía" de la segunda la
    marcaría como inconclusa aunque el servidor sea vulnerable por esa vía
    también.
    """
    traversal_prefix = "../" * depth
    payloads: list[WritePayload] = []

    outside_target = _new_write_target(OUTSIDE_DIR)
    payloads.append(WritePayload("absolute_outside_write", outside_target, _random_write_token(), outside_target))

    dotdot_outside_target = _new_write_target(OUTSIDE_DIR)
    dotdot_outside_relative = f"{traversal_prefix}{dotdot_outside_target.removeprefix('/')}"
    payloads.append(
        WritePayload("dotdot_outside_write", dotdot_outside_target, _random_write_token(), dotdot_outside_relative)
    )

    dotslash_outside_target = _new_write_target(OUTSIDE_DIR)
    dotslash_outside_relative = f"{traversal_prefix}{dotslash_outside_target.removeprefix('/')}"
    payloads.append(
        WritePayload(
            "dotslash_outside_write", dotslash_outside_target, _random_write_token(),
            f"./{dotslash_outside_relative}",
        )
    )

    sibling_dir = _sibling_dir(fs_root)

    sibling_target = _new_write_target(sibling_dir)
    payloads.append(WritePayload("absolute_sibling_write", sibling_target, _random_write_token(), sibling_target))

    dotdot_sibling_target = _new_write_target(sibling_dir)
    dotdot_sibling_relative = f"{traversal_prefix}{dotdot_sibling_target.removeprefix('/')}"
    payloads.append(
        WritePayload(
            "dotdot_sibling_write", dotdot_sibling_target, _random_write_token(), dotdot_sibling_relative,
        )
    )

    link_path = f"{fs_root.rstrip('/')}/lynceus-link-{uuid.uuid4().hex}"
    link_target = _new_write_target(OUTSIDE_DIR)
    payloads.append(
        WritePayload(
            "symlink_write", link_target, _random_write_token(), link_path,
            symlink_path=link_path, symlink_target=link_target,
        )
    )

    return payloads


@dataclass(frozen=True)
class WritePositiveControlPayload:
    target_path: str
    token: str
    value: str


def build_positive_control_write_payload(fs_root: str = DEFAULT_FS_ROOT) -> WritePositiveControlPayload:
    """Una ruta nueva (que no debe existir) dentro del límite, con un token
    propio: control positivo informativo que comprueba si la misma
    tool/parámetro puede siquiera escribir dentro de su propio límite. No es
    una carga de ataque y nunca produce un Finding.
    """
    path = f"{fs_root.rstrip('/')}/lynceus-write-positive-{uuid.uuid4().hex}"
    token = _random_write_token()
    return WritePositiveControlPayload(target_path=path, token=token, value=path)


@dataclass(frozen=True)
class SsrfPayload:
    technique: str
    value: str
    token: str | None = None
    canary_path: str | None = None
    canary_content: str | None = None


def build_ssrf_payloads(receiver_name: str, receiver_ip: str) -> list[SsrfPayload]:
    """Cargas fijas de SSRF: dos apuntan al receptor (por nombre y por IP),
    cada una con su propio token aleatorio; la tercera es un canario de
    lectura local, igual que en path traversal. Nada específico de un caso
    concreto: `receiver_name`/`receiver_ip` son los únicos datos del entorno.
    """
    host_token = _random_token()
    ip_token = _random_token()
    canary_path = _random_canary_path()
    canary_content = _random_canary_content()
    return [
        SsrfPayload(technique="host_url", value=f"http://{receiver_name}:8080/{host_token}", token=host_token),
        SsrfPayload(technique="ip_url", value=f"http://{receiver_ip}:8080/{ip_token}", token=ip_token),
        SsrfPayload(
            technique="file_canary",
            value=f"file://{canary_path}",
            canary_path=canary_path,
            canary_content=canary_content,
        ),
    ]
