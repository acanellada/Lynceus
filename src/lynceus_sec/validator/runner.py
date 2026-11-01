"""Ejecuta harness.py dentro del sandbox de Docker para un caso del benchmark."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

HARNESS_PATH = Path(__file__).resolve().with_name("harness.py")
RECEIVER_PATH = Path(__file__).resolve().with_name("receiver.py")
DEFAULT_IMAGE = "lynceus-sandbox:0.1"
SANDBOX_UID = 10001

# Script de una sola pieza, sin dependencias ajenas a la biblioteca estándar:
# se ejecuta dentro de un contenedor efímero en la red interna para comprobar
# que no hay salida real a internet (ni TCP directo ni resolución DNS) antes
# de lanzar ningún intento de SSRF. Falla cerrado: cualquier salida que no
# sea exactamente "ISOLATION_OK" se trata como aislamiento no confirmado.
_ISOLATION_CHECK_SCRIPT = (
    "import socket, sys\n"
    "socket.setdefaulttimeout(2.0)\n"
    "try:\n"
    "    with socket.create_connection(('1.1.1.1', 443), timeout=2.0):\n"
    "        tcp_reachable = True\n"
    "except OSError:\n"
    "    tcp_reachable = False\n"
    "try:\n"
    "    socket.getaddrinfo('example.com', 443)\n"
    "    dns_resolves = True\n"
    "except OSError:\n"
    "    dns_resolves = False\n"
    "if tcp_reachable or dns_resolves:\n"
    "    print(f'ISOLATION_FAILED tcp_reachable={tcp_reachable} dns_resolves={dns_resolves}')\n"
    "    sys.exit(1)\n"
    "print('ISOLATION_OK')\n"
)


class RunnerError(RuntimeError):
    pass


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _image_exists(image: str) -> bool:
    proc = subprocess.run(["docker", "image", "inspect", image], check=False, capture_output=True)
    return proc.returncode == 0


def _security_flags(memory: str, cpus: str, pids_limit: int) -> list[str]:
    """Flags de endurecimiento comunes a servidor, receptor y comprobación de aislamiento."""
    return [
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(pids_limit),
        "--memory", memory,
        "--memory-swap", memory,
        "--cpus", cpus,
        "--user", f"{SANDBOX_UID}:{SANDBOX_UID}",
        "-e", "HOME=/tmp",
    ]


def build_docker_command(
    case_dir: Path,
    *,
    image: str = DEFAULT_IMAGE,
    timeout: float = 20.0,
    memory: str = "256m",
    cpus: str = "1",
    pids_limit: int = 64,
    container_name: str | None = None,
    network: str = "none",
    extra_harness_args: list[str] | None = None,
) -> tuple[str, list[str]]:
    """Construye el comando `docker run` del sandbox. No ejecuta nada.

    `network` solo cambia para los casos de SSRF (red interna); el resto de
    clases siguen con el valor por defecto `"none"`.
    """
    name = container_name or f"lynceus-sandbox-{uuid.uuid4().hex[:12]}"
    cmd = [
        "docker", "run", "--rm",
        "--name", name,
        "--network", network,
        *_security_flags(memory, cpus, pids_limit),
        "-v", f"{Path(case_dir).resolve()}:/case:ro",
        "-v", f"{HARNESS_PATH}:/harness/harness.py:ro",
        image,
        "python", "/harness/harness.py", "/case/server.py", "--timeout", str(timeout),
    ]
    cmd += extra_harness_args or []
    return name, cmd


def build_network_create_cmd(name: str) -> list[str]:
    return ["docker", "network", "create", "--internal", name]


def build_network_rm_cmd(name: str) -> list[str]:
    return ["docker", "network", "rm", name]


def create_internal_network() -> str:
    """Crea una red Docker `--internal` con nombre aleatorio y la devuelve."""
    name = f"lynceus-net-{uuid.uuid4().hex[:12]}"
    proc = subprocess.run(build_network_create_cmd(name), check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        raise RunnerError(f"No se pudo crear la red interna {name!r}: {detail}")
    return name


def remove_network(name: str) -> None:
    """Borra la red; mejor esfuerzo, no lanza si ya no existe o falla."""
    subprocess.run(build_network_rm_cmd(name), check=False, capture_output=True, text=True)


def kill_container(name: str) -> None:
    """Mata un contenedor por nombre; mejor esfuerzo, no lanza si ya no existe."""
    subprocess.run(["docker", "kill", name], check=False, capture_output=True)


def build_receiver_command(
    network: str,
    *,
    image: str = DEFAULT_IMAGE,
    memory: str = "256m",
    cpus: str = "1",
    pids_limit: int = 64,
    container_name: str | None = None,
) -> tuple[str, list[str]]:
    """Comando del receptor de canarios: mismas protecciones que el servidor,
    en la red interna, sin publicar ningún puerto hacia el host."""
    name = container_name or f"lynceus-receiver-{uuid.uuid4().hex[:12]}"
    cmd = [
        "docker", "run", "-d", "--rm",
        "--name", name,
        "--network", network,
        *_security_flags(memory, cpus, pids_limit),
        "-v", f"{RECEIVER_PATH}:/harness/receiver.py:ro",
        image,
        "python", "/harness/receiver.py",
    ]
    return name, cmd


def _wait_for_running(name: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        proc = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            check=False, capture_output=True, text=True,
        )
        if proc.returncode == 0 and proc.stdout.strip() == "true":
            return True
        time.sleep(0.2)
    return False


def get_container_ip(name: str, network: str) -> str:
    fmt = f"{{{{(index .NetworkSettings.Networks \"{network}\").IPAddress}}}}"
    proc = subprocess.run(
        ["docker", "inspect", "-f", fmt, name], check=False, capture_output=True, text=True,
    )
    ip = proc.stdout.strip()
    if proc.returncode != 0 or not ip:
        detail = proc.stderr.strip() or "sin IP asignada"
        raise RunnerError(f"No se pudo obtener la IP de {name!r} en la red {network!r}: {detail}")
    return ip


def start_receiver(network: str, *, image: str = DEFAULT_IMAGE, ready_timeout: float = 5.0) -> tuple[str, str]:
    """Arranca el receptor en la red interna y devuelve (nombre, IP)."""
    _check_docker_and_image(image)
    name, cmd = build_receiver_command(network, image=image)
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        raise RunnerError(f"No se pudo arrancar el receptor: {detail}")
    if not _wait_for_running(name, ready_timeout):
        kill_container(name)
        raise RunnerError(f"El receptor {name!r} no llegó a estar en marcha")
    ip = get_container_ip(name, network)
    return name, ip


def stop_receiver(name: str) -> None:
    subprocess.run(["docker", "rm", "-f", name], check=False, capture_output=True)


def read_receiver_log(name: str) -> list[dict[str, Any]]:
    """Lee `docker logs` del receptor y devuelve las líneas JSON válidas."""
    proc = subprocess.run(["docker", "logs", name], check=False, capture_output=True, text=True)
    entries: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def build_isolation_check_command(
    network: str, *, image: str = DEFAULT_IMAGE, container_name: str | None = None,
) -> tuple[str, list[str]]:
    name = container_name or f"lynceus-isolation-{uuid.uuid4().hex[:12]}"
    cmd = [
        "docker", "run", "--rm",
        "--name", name,
        "--network", network,
        *_security_flags("64m", "1", 16),
        image,
        "python", "-c", _ISOLATION_CHECK_SCRIPT,
    ]
    return name, cmd


def check_network_isolation(network: str, *, image: str = DEFAULT_IMAGE, timeout: float = 10.0) -> None:
    """Comprueba que la red interna no tiene salida real antes de cualquier intento.

    Falla cerrado: aborta salvo que la comprobación confirme positivamente
    el bloqueo (ni TCP directo ni resolución DNS); timeout, salida ambigua o
    fallo al arrancar el contenedor de comprobación también abortan.
    """
    _, cmd = build_isolation_check_command(network, image=image)
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RunnerError(
            "La comprobación de aislamiento de red no terminó a tiempo: resultado ambiguo, se aborta"
        ) from exc

    output = proc.stdout.strip()
    if proc.returncode != 0 or output != "ISOLATION_OK":
        detail = output or proc.stderr.strip() or f"código de salida {proc.returncode}"
        raise RunnerError(f"La red interna no está aislada (o el resultado es ambiguo), se aborta: {detail}")


def parse_harness_output(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if "error" in payload:
        raise RunnerError(f"El harness reportó un error: {payload['error']}")
    if "tools" not in payload:
        raise RunnerError(f"JSON del harness sin clave 'tools': {payload!r}")
    return payload["tools"]


def _check_docker_and_image(image: str) -> None:
    if not _docker_available():
        raise RunnerError("Docker no está disponible en el PATH")
    if not _image_exists(image):
        raise RunnerError(
            f"La imagen {image!r} no existe; constrúyela con "
            f"'docker build -t {image} sandbox/'"
        )


def _execute(case_dir: Path, cmd: list[str], container_name: str, wall_clock_timeout: float) -> dict[str, Any]:
    """Ejecuta el comando docker, mata el contenedor si expira y devuelve el JSON del harness."""
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=wall_clock_timeout)
    except subprocess.TimeoutExpired as exc:
        kill_container(container_name)
        raise RunnerError(f"El harness no terminó en {wall_clock_timeout}s para {case_dir}") from exc

    if proc.returncode != 0:
        try:
            detail = json.loads(proc.stdout).get("error", proc.stdout)
        except json.JSONDecodeError:
            detail = proc.stdout.strip()
        stderr = proc.stderr.strip()
        if stderr:
            detail = f"{detail} | stderr: {stderr}"
        raise RunnerError(f"El harness falló (code={proc.returncode}) para {case_dir}: {detail}")

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RunnerError(f"Salida del harness no es JSON válido para {case_dir}: {proc.stdout!r}") from exc


def run_harness(
    case_dir: Path,
    *,
    image: str = DEFAULT_IMAGE,
    timeout: float = 20.0,
    network: str = "none",
    container_name: str | None = None,
) -> list[dict[str, Any]]:
    _check_docker_and_image(image)
    container_name, cmd = build_docker_command(
        case_dir, image=image, timeout=timeout, network=network, container_name=container_name,
    )
    payload = _execute(case_dir, cmd, container_name, wall_clock_timeout=timeout + 10)
    return parse_harness_output(payload)


def run_validate(
    case_dir: Path,
    attempts: list[dict[str, Any]],
    *,
    image: str = DEFAULT_IMAGE,
    call_timeout: float = 15.0,
    total_timeout: float | None = None,
    network: str = "none",
    container_name: str | None = None,
) -> list[dict[str, Any]]:
    """Ejecuta `attempts` dentro del sandbox (un proceso de servidor nuevo por intento).

    `total_timeout` y el tiempo máximo del subprocess de Docker escalan con el
    número de intentos si no se fija `total_timeout` explícitamente. `network`
    y `container_name` solo los fija el llamador (SSRF) para poder matar el
    contenedor por nombre si hace falta abortar; el resto de clases usan los
    valores por defecto.
    """
    _check_docker_and_image(image)

    if total_timeout is None:
        total_timeout = max(30.0, len(attempts) * (call_timeout + 5.0))
    wall_clock_timeout = total_timeout + 20.0

    extra_args = [
        "--mode", "validate",
        "--attempts", json.dumps(attempts),
        "--total-timeout", str(total_timeout),
    ]
    container_name, cmd = build_docker_command(
        case_dir, image=image, timeout=call_timeout, network=network,
        container_name=container_name, extra_harness_args=extra_args,
    )
    payload = _execute(case_dir, cmd, container_name, wall_clock_timeout=wall_clock_timeout)

    if "error" in payload:
        raise RunnerError(f"El harness reportó un error en la validación: {payload['error']}")
    if "results" not in payload:
        raise RunnerError(f"JSON de validación sin clave 'results': {payload!r}")
    return payload["results"]
