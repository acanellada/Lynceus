"""Ejecuta harness.py dentro del sandbox de Docker para un caso del benchmark."""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

HARNESS_PATH = Path(__file__).resolve().with_name("harness.py")
DEFAULT_IMAGE = "lynceus-sandbox:0.1"
SANDBOX_UID = 10001


class RunnerError(RuntimeError):
    pass


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _image_exists(image: str) -> bool:
    proc = subprocess.run(["docker", "image", "inspect", image], check=False, capture_output=True)
    return proc.returncode == 0


def build_docker_command(
    case_dir: Path,
    *,
    image: str = DEFAULT_IMAGE,
    timeout: float = 20.0,
    memory: str = "256m",
    cpus: str = "1",
    pids_limit: int = 64,
    container_name: str | None = None,
    extra_harness_args: list[str] | None = None,
) -> tuple[str, list[str]]:
    """Construye el comando `docker run` del sandbox. No ejecuta nada."""
    name = container_name or f"lynceus-sandbox-{uuid.uuid4().hex[:12]}"
    cmd = [
        "docker", "run", "--rm",
        "--name", name,
        "--network", "none",
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
        "-v", f"{Path(case_dir).resolve()}:/case:ro",
        "-v", f"{HARNESS_PATH}:/harness/harness.py:ro",
        image,
        "python", "/harness/harness.py", "/case/server.py", "--timeout", str(timeout),
    ]
    cmd += extra_harness_args or []
    return name, cmd


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
        subprocess.run(["docker", "kill", container_name], check=False, capture_output=True)
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


def run_harness(case_dir: Path, *, image: str = DEFAULT_IMAGE, timeout: float = 20.0) -> list[dict[str, Any]]:
    _check_docker_and_image(image)
    container_name, cmd = build_docker_command(case_dir, image=image, timeout=timeout)
    payload = _execute(case_dir, cmd, container_name, wall_clock_timeout=timeout + 10)
    return parse_harness_output(payload)


def run_validate(
    case_dir: Path,
    attempts: list[dict[str, Any]],
    *,
    image: str = DEFAULT_IMAGE,
    call_timeout: float = 15.0,
    total_timeout: float | None = None,
) -> list[dict[str, Any]]:
    """Ejecuta `attempts` dentro del sandbox (un proceso de servidor nuevo por intento).

    `total_timeout` y el tiempo máximo del subprocess de Docker escalan con el
    número de intentos si no se fija `total_timeout` explícitamente.
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
        case_dir, image=image, timeout=call_timeout, extra_harness_args=extra_args,
    )
    payload = _execute(case_dir, cmd, container_name, wall_clock_timeout=wall_clock_timeout)

    if "error" in payload:
        raise RunnerError(f"El harness reportó un error en la validación: {payload['error']}")
    if "results" not in payload:
        raise RunnerError(f"JSON de validación sin clave 'results': {payload!r}")
    return payload["results"]
