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
    return name, cmd


def parse_harness_output(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if "error" in payload:
        raise RunnerError(f"El harness reportó un error: {payload['error']}")
    if "tools" not in payload:
        raise RunnerError(f"JSON del harness sin clave 'tools': {payload!r}")
    return payload["tools"]


def run_harness(case_dir: Path, *, image: str = DEFAULT_IMAGE, timeout: float = 20.0) -> list[dict[str, Any]]:
    if not _docker_available():
        raise RunnerError("Docker no está disponible en el PATH")
    if not _image_exists(image):
        raise RunnerError(
            f"La imagen {image!r} no existe; constrúyela con "
            f"'docker build -t {image} sandbox/'"
        )

    container_name, cmd = build_docker_command(case_dir, image=image, timeout=timeout)

    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=timeout + 10)
    except subprocess.TimeoutExpired as exc:
        subprocess.run(["docker", "kill", container_name], check=False, capture_output=True)
        raise RunnerError(f"El harness no terminó en {timeout + 10}s para {case_dir}") from exc

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
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RunnerError(f"Salida del harness no es JSON válido para {case_dir}: {proc.stdout!r}") from exc

    return parse_harness_output(payload)
